using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;

namespace OpenBack.AppAuth
{
    /// <summary>
    /// A <see cref="DelegatingHandler"/> that adds <c>Authorization: Bearer &lt;access token&gt;</c> (renewed when needed) to
    /// every request: use it for the HttpClient that calls YOUR API.
    /// <code>
    /// var api = new HttpClient(new AppAuthHttpHandler(auth, new HttpClientHandler()));
    /// // IHttpClientFactory: services.AddHttpClient("api").AddHttpMessageHandler(() => new AppAuthHttpHandler(auth));
    /// </code>
    /// Do not use it for the pool's own HttpClient (<see cref="AppAuthClientOptions.HttpClient"/>).
    /// </summary>
    public sealed class AppAuthHttpHandler : DelegatingHandler
    {
        private readonly AppAuthClient _client;

        /// <summary>For IHttpClientFactory pipelines (the factory sets the inner handler).</summary>
        public AppAuthHttpHandler(AppAuthClient client)
        {
            _client = client ?? throw new ArgumentNullException(nameof(client));
        }

        /// <summary>For a plain <c>new HttpClient(handler)</c>.</summary>
        public AppAuthHttpHandler(AppAuthClient client, HttpMessageHandler innerHandler) : base(innerHandler)
        {
            _client = client ?? throw new ArgumentNullException(nameof(client));
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var token = await _client.GetAccessTokenAsync(cancellationToken).ConfigureAwait(false);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
    }
}
