using System.Collections.Concurrent;
using System.Threading;
using System.Threading.Tasks;

namespace OpenBack.AppAuth
{
    /// <summary>
    /// Where <see cref="AppAuthClient"/> keeps the session (a JSON string under the key
    /// <c>openback.auth.&lt;clientId&gt;</c>) and the pending hosted sign-in (<c>&lt;key&gt;.pkce</c>).
    /// Implement it to use your own store: a file, a database row, the OS keychain, an ASP.NET session...
    /// The values are secrets (refresh tokens): store them protected.
    /// </summary>
    public interface ITokenStorage
    {
        /// <summary>The value under <paramref name="key"/>, or null.</summary>
        Task<string?> GetAsync(string key, CancellationToken cancellationToken = default);

        /// <summary>Stores <paramref name="value"/> under <paramref name="key"/> (replacing it atomically when possible).</summary>
        Task SetAsync(string key, string value, CancellationToken cancellationToken = default);

        /// <summary>Removes the value under <paramref name="key"/> (no error when missing).</summary>
        Task RemoveAsync(string key, CancellationToken cancellationToken = default);
    }

    /// <summary>The default storage: in memory, lost when the process ends (servers, CLIs, tests).</summary>
    public sealed class InMemoryTokenStorage : ITokenStorage
    {
        private readonly ConcurrentDictionary<string, string> _data = new ConcurrentDictionary<string, string>();

        public Task<string?> GetAsync(string key, CancellationToken cancellationToken = default)
        {
            return Task.FromResult(_data.TryGetValue(key, out var value) ? value : null);
        }

        public Task SetAsync(string key, string value, CancellationToken cancellationToken = default)
        {
            _data[key] = value;
            return Task.CompletedTask;
        }

        public Task RemoveAsync(string key, CancellationToken cancellationToken = default)
        {
            _data.TryRemove(key, out _);
            return Task.CompletedTask;
        }
    }
}
