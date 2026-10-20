using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using OpenBack.AppAuth.Internal;

namespace OpenBack.AppAuth
{
    /// <summary>JWT decoding WITHOUT verification (for display only: never trust it for access decisions; use
    /// <see cref="TokenVerifier"/>).</summary>
    public static class Jwt
    {
        /// <summary>The claims of a JWT, unverified; null when it is not a JWT.</summary>
        public static JsonElement? DecodePayload(string? token) => Part(token, 1);

        /// <summary>The header of a JWT, unverified; null when it is not a JWT.</summary>
        public static JsonElement? DecodeHeader(string? token) => Part(token, 0);

        private static JsonElement? Part(string? token, int index)
        {
            if (string.IsNullOrEmpty(token)) return null;
            var parts = token!.Split('.');
            if (parts.Length != 3) return null;
            try
            {
                var json = Json.Parse(Encoding.UTF8.GetString(Base64Url.Decode(parts[index])));
                return json.ValueKind == JsonValueKind.Object ? json : (JsonElement?)null;
            }
            catch (Exception e) when (e is FormatException || e is JsonException || e is ArgumentException)
            {
                return null;
            }
        }

        /// <summary>True when <c>aud</c> (a string, or an array) names one of <paramref name="clientIds"/>.</summary>
        internal static bool AudienceMatches(JsonElement claims, IEnumerable<string> clientIds)
        {
            if (claims.ValueKind != JsonValueKind.Object || !claims.TryGetProperty("aud", out var aud)) return false;
            var wanted = new HashSet<string>(clientIds, StringComparer.Ordinal);
            if (aud.ValueKind == JsonValueKind.String) return wanted.Contains(aud.GetString()!);
            if (aud.ValueKind == JsonValueKind.Array)
            {
                foreach (var a in aud.EnumerateArray())
                    if (a.ValueKind == JsonValueKind.String && wanted.Contains(a.GetString()!)) return true;
            }
            return false;
        }

        /// <summary>The first audience that is one of <paramref name="clientIds"/>.</summary>
        internal static string? MatchedAudience(JsonElement claims, IEnumerable<string> clientIds)
        {
            if (!claims.TryGetProperty("aud", out var aud)) return null;
            var wanted = new HashSet<string>(clientIds, StringComparer.Ordinal);
            if (aud.ValueKind == JsonValueKind.String) return wanted.Contains(aud.GetString()!) ? aud.GetString() : null;
            if (aud.ValueKind == JsonValueKind.Array)
                foreach (var a in aud.EnumerateArray())
                    if (a.ValueKind == JsonValueKind.String && wanted.Contains(a.GetString()!)) return a.GetString();
            return null;
        }
    }
}
