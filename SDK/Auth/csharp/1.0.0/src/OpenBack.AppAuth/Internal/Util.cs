using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OpenBack.AppAuth.Internal
{
    /// <summary>Base64url without padding (RFC 4648 section 5), as used by JOSE and PKCE.</summary>
    internal static class Base64Url
    {
        public static string Encode(byte[] data)
        {
            return Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }

        /// <exception cref="FormatException">The text is not base64url.</exception>
        public static byte[] Decode(string text)
        {
            if (text == null) throw new FormatException("null base64url text");
            foreach (var c in text)
            {
                if (!(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_'))
                    throw new FormatException("invalid base64url character");
            }
            var s = text.Replace('-', '+').Replace('_', '/');
            switch (s.Length % 4)
            {
                case 0: break;
                case 2: s += "=="; break;
                case 3: s += "="; break;
                default: throw new FormatException("invalid base64url length");
            }
            return Convert.FromBase64String(s);
        }
    }

    internal static class Crypto
    {
        /// <summary>A random base64url string from <paramref name="bytes"/> CSPRNG bytes.</summary>
        public static string RandomString(int bytes)
        {
            var buffer = new byte[bytes];
            using (var rng = RandomNumberGenerator.Create()) rng.GetBytes(buffer);
            return Base64Url.Encode(buffer);
        }

        /// <summary>The PKCE S256 challenge of a verifier: base64url(SHA-256(ASCII(verifier))).</summary>
        public static string CodeChallenge(string verifier)
        {
            using (var sha = SHA256.Create())
                return Base64Url.Encode(sha.ComputeHash(Encoding.ASCII.GetBytes(verifier)));
        }

        /// <summary>Constant-time comparison of two strings (the length is not secret).</summary>
        public static bool FixedTimeEquals(string? a, string? b)
        {
            if (a == null || b == null) return false;
            var x = Encoding.UTF8.GetBytes(a);
            var y = Encoding.UTF8.GetBytes(b);
            if (x.Length != y.Length) return false;
            var diff = 0;
            for (var i = 0; i < x.Length; i++) diff |= x[i] ^ y[i];
            return diff == 0;
        }
    }

    internal static class Json
    {
        /// <summary>The service speaks snake_case JSON.</summary>
        public static readonly JsonSerializerOptions Options = new JsonSerializerOptions
        {
            PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
            PropertyNameCaseInsensitive = true,
            DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        };

        public static JsonElement Parse(string text)
        {
            using (var doc = JsonDocument.Parse(text)) return doc.RootElement.Clone();
        }

        public static T? To<T>(JsonElement element) where T : class
        {
            if (element.ValueKind != JsonValueKind.Object && element.ValueKind != JsonValueKind.Array) return null;
            return JsonSerializer.Deserialize<T>(element.GetRawText(), Options);
        }

        public static string? Str(JsonElement obj, string name)
        {
            if (obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String)
                return v.GetString();
            return null;
        }

        public static long? Num(JsonElement obj, string name)
        {
            if (obj.ValueKind != JsonValueKind.Object || !obj.TryGetProperty(name, out var v) || v.ValueKind != JsonValueKind.Number)
                return null;
            if (v.TryGetInt64(out var l)) return l;
            return (long)Math.Floor(v.GetDouble());
        }

        public static bool Bool(JsonElement obj, string name)
        {
            return obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.True;
        }

        public static IReadOnlyList<string> StrList(JsonElement obj, string name)
        {
            var list = new List<string>();
            if (obj.ValueKind == JsonValueKind.Object && obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in v.EnumerateArray())
                    if (item.ValueKind == JsonValueKind.String) list.Add(item.GetString()!);
            }
            return list;
        }

        /// <summary>A JSON body without the null members (like JavaScript's undefined fields).</summary>
        public static Dictionary<string, object?> Body(params (string Name, object? Value)[] members)
        {
            var body = new Dictionary<string, object?>();
            foreach (var m in members)
                if (m.Value != null) body[m.Name] = m.Value;
            return body;
        }
    }

    internal static class Query
    {
        /// <summary>The query parameters of a URL (or of a bare query string), form-decoded. First value wins.</summary>
        public static Dictionary<string, string> Parse(string urlOrQuery)
        {
            var result = new Dictionary<string, string>(StringComparer.Ordinal);
            if (string.IsNullOrEmpty(urlOrQuery)) return result;
            var q = urlOrQuery;
            var hash = q.IndexOf('#');
            if (hash >= 0) q = q.Substring(0, hash);
            var mark = q.IndexOf('?');
            if (mark >= 0) q = q.Substring(mark + 1);
            else if (q.Contains("://")) return result;
            foreach (var part in q.Split('&'))
            {
                if (part.Length == 0) continue;
                var eq = part.IndexOf('=');
                var name = Decode(eq < 0 ? part : part.Substring(0, eq));
                var value = eq < 0 ? "" : Decode(part.Substring(eq + 1));
                if (!result.ContainsKey(name)) result[name] = value;
            }
            return result;
        }

        public static string Build(IEnumerable<KeyValuePair<string, string?>> parameters)
        {
            var sb = new StringBuilder();
            foreach (var p in parameters)
            {
                if (p.Value == null) continue;
                if (sb.Length > 0) sb.Append('&');
                sb.Append(Uri.EscapeDataString(p.Key)).Append('=').Append(Uri.EscapeDataString(p.Value));
            }
            return sb.ToString();
        }

        private static string Decode(string s)
        {
            return Uri.UnescapeDataString(s.Replace('+', ' '));
        }
    }

    internal static class Issuer
    {
        public static string Normalize(string issuer)
        {
            if (string.IsNullOrWhiteSpace(issuer)) throw new ArgumentException("The issuer (the user pool's address) is required.", nameof(issuer));
            var s = issuer.Trim().TrimEnd('/');
            if (!Uri.TryCreate(s, UriKind.Absolute, out var uri) || (uri.Scheme != "https" && uri.Scheme != "http"))
                throw new ArgumentException("The issuer must be an absolute http(s) URL.", nameof(issuer));
            return s;
        }
    }
}
