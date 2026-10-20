using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using OpenBack.AppAuth.Internal;

namespace OpenBack.AppAuth
{
    /// <summary>The desktop loopback flow (RFC 8252 section 7.3): an HttpListener on the registered 127.0.0.1 / localhost
    /// redirect URI receives the hosted page's redirect.</summary>
    internal static class LoopbackSignIn
    {
        public static async Task<PoolUser?> RunAsync(AppAuthClient client, string redirect, SystemBrowserOptions browser,
            AuthorizationRequestOptions authorize, CancellationToken ct)
        {
            var uri = new Uri(redirect);
            var host = uri.Host.Trim('[', ']');
            if (uri.Scheme != "http" || !(host == "127.0.0.1" || host == "localhost" || host == "::1"))
                throw new ArgumentException("The system browser sign-in needs a loopback redirect URI: http://127.0.0.1:<port>/<path>.");

            using (var listener = new HttpListener())
            {
                listener.Prefixes.Add("http://" + uri.Authority + "/");
                try
                {
                    listener.Start();
                }
                catch (HttpListenerException e)
                {
                    throw new AppAuthException(0, "loopback_unavailable", "The loopback redirect port is not available: " + uri.Authority, null, e);
                }

                var request = await client.BuildAuthorizationRequestAsync(authorize, ct).ConfigureAwait(false);
                await (browser.OpenBrowser ?? OpenSystemBrowser)(request.Url).ConfigureAwait(false);

                using (var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct))
                {
                    timeout.CancelAfter(browser.Timeout);
                    using (timeout.Token.Register(() => { try { listener.Stop(); } catch { /* already stopped */ } }))
                    {
                        var expectedPath = uri.AbsolutePath.TrimEnd('/');
                        while (true)
                        {
                            HttpListenerContext context;
                            try
                            {
                                context = await listener.GetContextAsync().ConfigureAwait(false);
                            }
                            catch (Exception e) when (e is HttpListenerException || e is ObjectDisposedException || e is InvalidOperationException)
                            {
                                ct.ThrowIfCancellationRequested();
                                throw new AppAuthException(0, "timeout", "The sign-in in the browser was not completed in time.", null, e);
                            }

                            var url = context.Request.Url;
                            var query = url == null ? "" : url.Query;
                            var parsed = Query.Parse(query);
                            if (url == null || url.AbsolutePath.TrimEnd('/') != expectedPath || (!parsed.ContainsKey("code") && !parsed.ContainsKey("error")))
                            {
                                Respond(context, 404, "<!doctype html><title>Not found</title>");
                                continue;   // favicon and other requests: keep waiting
                            }

                            try
                            {
                                var user = await client.HandleRedirectCallbackAsync(redirect.Split('?')[0] + query, ct).ConfigureAwait(false);
                                Respond(context, 200, browser.SuccessHtml);
                                return user;
                            }
                            catch
                            {
                                Respond(context, 400, browser.ErrorHtml);
                                throw;
                            }
                        }
                    }
                }
            }
        }

        private static void Respond(HttpListenerContext context, int status, string html)
        {
            try
            {
                var bytes = Encoding.UTF8.GetBytes(html);
                context.Response.StatusCode = status;
                context.Response.ContentType = "text/html; charset=utf-8";
                context.Response.Headers["Cache-Control"] = "no-store";
                context.Response.Headers["Referrer-Policy"] = "no-referrer";
                context.Response.ContentLength64 = bytes.Length;
                context.Response.OutputStream.Write(bytes, 0, bytes.Length);
                context.Response.OutputStream.Close();
            }
            catch (Exception)
            {
                // The browser went away: nothing to do.
            }
        }

        /// <summary>Opens a URL in the user's default browser.</summary>
        public static Task OpenSystemBrowser(Uri url)
        {
            var target = url.AbsoluteUri;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                Process.Start(new ProcessStartInfo(target) { UseShellExecute = true })?.Dispose();
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                Process.Start(new ProcessStartInfo("open", "\"" + target + "\"") { UseShellExecute = false })?.Dispose();
            else
                Process.Start(new ProcessStartInfo("xdg-open", "\"" + target + "\"") { UseShellExecute = false })?.Dispose();
            return Task.CompletedTask;
        }
    }
}
