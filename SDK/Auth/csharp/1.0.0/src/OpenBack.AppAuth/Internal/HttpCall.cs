using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace OpenBack.AppAuth.Internal
{
    internal static class HttpCall
    {
        /// <summary>Sends a request and returns the JSON answer; errors become <see cref="AppAuthException"/>
        /// (network errors: status 0, <c>network_error</c> / <c>timeout</c>). Cancellation by the caller propagates.</summary>
        public static async Task<JsonElement> SendAsync(HttpClient http, HttpRequestMessage request, CancellationToken ct)
        {
            HttpResponseMessage response;
            try
            {
                response = await http.SendAsync(request, ct).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch (TaskCanceledException e)
            {
                throw new AppAuthException(0, "timeout", "The request to the user pool timed out.", null, e);
            }
            catch (HttpRequestException e)
            {
                throw new AppAuthException(0, "network_error", "The user pool could not be reached.", null, e);
            }
            using (response)
            {
                var text = response.Content == null ? "" : await response.Content.ReadAsStringAsync().ConfigureAwait(false);
                JsonElement data = default;
                if (!string.IsNullOrWhiteSpace(text))
                {
                    try { data = Json.Parse(text); }
                    catch (JsonException) { data = default; }
                }
                var status = (int)response.StatusCode;
                if (status < 200 || status > 299) throw AppAuthException.FromResponse(status, response.ReasonPhrase, data);
                return data;
            }
        }

        /// <summary><c>client_secret_basic</c>: Basic base64(urlencode(id) ":" urlencode(secret)) (RFC 6749 2.3.1).</summary>
        public static AuthenticationHeaderValue BasicAuth(string clientId, string secret)
        {
            var raw = Uri.EscapeDataString(clientId) + ":" + Uri.EscapeDataString(secret);
            return new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.UTF8.GetBytes(raw)));
        }
    }
}
