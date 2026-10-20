using System;
using System.Collections.Generic;
using System.Text.Json;
using OpenBack.AppAuth.Internal;

namespace OpenBack.AppAuth
{
    /// <summary>
    /// An error of the user pool, of the network or of a token. <see cref="Code"/> is the service's code
    /// (<c>invalid_credentials</c>, <c>too_many_requests</c>, <c>weak_password</c>, <c>token_expired</c>...), or
    /// <c>http_&lt;status&gt;</c> when the answer had none; <see cref="Status"/> is the HTTP status (0 for network errors).
    /// </summary>
    public class AppAuthException : Exception
    {
        public AppAuthException(int status, string code, string? message = null, JsonElement? detail = null, Exception? innerException = null)
            : base(string.IsNullOrEmpty(message) ? code : message, innerException)
        {
            Status = status;
            Code = string.IsNullOrEmpty(code) ? "http_" + status : code;
            Detail = detail;
        }

        /// <summary>The HTTP status of the answer; 0 when no answer arrived (network error, timeout).</summary>
        public int Status { get; }

        /// <summary>The service's error code, e.g. <c>invalid_credentials</c>; <c>http_&lt;status&gt;</c> when none.</summary>
        public string Code { get; }

        /// <summary>The raw <c>detail</c> of the answer (an object, a string or a validation list), when present.</summary>
        public JsonElement? Detail { get; }

        /// <summary>For <c>weak_password</c>: the password policy's problems (<c>detail.problems</c>).</summary>
        public IReadOnlyList<string> Problems
        {
            get { return Detail.HasValue ? Json.StrList(Detail.Value, "problems") : Array.Empty<string>(); }
        }

        /// <summary>True when the error means the local session is dead (a <c>token_*</c> 401 or <c>invalid_refresh_token</c>).</summary>
        public bool IsSessionEnded
        {
            get { return Status == 401 && (Code.StartsWith("token_", StringComparison.Ordinal) || Code == "invalid_refresh_token"); }
        }

        /// <summary>Maps an error answer: <c>{"detail": {"code","message"}}</c>, <c>{"detail": "text"}</c>, a FastAPI
        /// validation list, or an OAuth <c>{"error","error_description"}</c>.</summary>
        internal static AppAuthException FromResponse(int status, string? reason, JsonElement body)
        {
            string? code = null, message = null;
            JsonElement? detail = null;
            if (body.ValueKind == JsonValueKind.Object)
            {
                if (body.TryGetProperty("detail", out var d))
                {
                    detail = d.Clone();
                    switch (d.ValueKind)
                    {
                        case JsonValueKind.Object:
                            code = Json.Str(d, "code");
                            message = Json.Str(d, "message");
                            break;
                        case JsonValueKind.String:
                            message = d.GetString();
                            break;
                        case JsonValueKind.Array:
                            foreach (var item in d.EnumerateArray())
                            {
                                message = Json.Str(item, "msg");
                                if (message != null) break;
                            }
                            break;
                    }
                }
                else if (body.TryGetProperty("error", out var e) && e.ValueKind == JsonValueKind.String)
                {
                    code = e.GetString();
                    message = Json.Str(body, "error_description") ?? code;
                }
            }
            code = string.IsNullOrEmpty(code) ? "http_" + status : code!;
            message = string.IsNullOrEmpty(message) ? (string.IsNullOrEmpty(reason) ? code : reason) : message;
            return new AppAuthException(status, code, message, detail);
        }
    }

    /// <summary>A token that did not pass verification (<see cref="TokenVerifier"/>). Always status 401.
    /// Codes: <c>malformed_token</c>, <c>invalid_algorithm</c>, <c>invalid_type</c>, <c>unknown_key</c>,
    /// <c>invalid_signature</c>, <c>invalid_issuer</c>, <c>invalid_audience</c>, <c>token_expired</c>,
    /// <c>token_not_yet_valid</c>, <c>invalid_nonce</c>.</summary>
    public sealed class TokenVerificationException : AppAuthException
    {
        public TokenVerificationException(string code, string message) : base(401, code, message) { }
    }
}
