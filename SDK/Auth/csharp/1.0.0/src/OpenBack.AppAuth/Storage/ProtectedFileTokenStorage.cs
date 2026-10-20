using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace OpenBack.AppAuth
{
    /// <summary>
    /// Windows desktop storage: one file per key, encrypted with DPAPI for the current Windows user
    /// (<c>CryptProtectData</c>, no extra package). Only the same Windows account on the same machine can read it back.
    /// Default folder: <c>%LOCALAPPDATA%\OpenBack\AppAuth</c>. Throws <see cref="PlatformNotSupportedException"/> on
    /// other operating systems (use the OS keychain there, through your own <see cref="ITokenStorage"/>).
    /// </summary>
    public sealed class ProtectedFileTokenStorage : ITokenStorage
    {
        private static readonly byte[] DefaultEntropy = Encoding.UTF8.GetBytes("openback.app-auth.csharp.v1");
        private readonly string _directory;
        private readonly byte[] _entropy;
        private readonly object _gate = new object();

        /// <param name="directory">The folder of the files (created when missing); default
        /// <c>%LOCALAPPDATA%\OpenBack\AppAuth</c>.</param>
        /// <param name="entropy">Optional additional entropy (an app-specific secret) mixed into the DPAPI encryption.</param>
        public ProtectedFileTokenStorage(string? directory = null, byte[]? entropy = null)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                throw new PlatformNotSupportedException("ProtectedFileTokenStorage uses Windows DPAPI.");
            _directory = directory ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "OpenBack", "AppAuth");
            _entropy = entropy != null && entropy.Length > 0 ? entropy : DefaultEntropy;
        }

        /// <summary>The folder holding the files.</summary>
        public string Directory => _directory;

        public Task<string?> GetAsync(string key, CancellationToken cancellationToken = default)
        {
            var path = PathOf(key);
            lock (_gate)
            {
                if (!File.Exists(path)) return Task.FromResult<string?>(null);
                try
                {
                    var plain = Dpapi.Unprotect(File.ReadAllBytes(path), _entropy);
                    return Task.FromResult<string?>(Encoding.UTF8.GetString(plain));
                }
                catch (CryptographicException)
                {
                    // Written by another user or machine, or damaged: as if missing.
                    return Task.FromResult<string?>(null);
                }
            }
        }

        public Task SetAsync(string key, string value, CancellationToken cancellationToken = default)
        {
            var path = PathOf(key);
            var data = Dpapi.Protect(Encoding.UTF8.GetBytes(value), _entropy);
            lock (_gate)
            {
                System.IO.Directory.CreateDirectory(_directory);
                var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
                File.WriteAllBytes(temp, data);
                try
                {
                    if (File.Exists(path)) File.Replace(temp, path, null);
                    else File.Move(temp, path);
                }
                finally
                {
                    if (File.Exists(temp)) File.Delete(temp);
                }
            }
            return Task.CompletedTask;
        }

        public Task RemoveAsync(string key, CancellationToken cancellationToken = default)
        {
            var path = PathOf(key);
            lock (_gate)
            {
                if (File.Exists(path)) File.Delete(path);
            }
            return Task.CompletedTask;
        }

        private string PathOf(string key)
        {
            if (string.IsNullOrEmpty(key)) throw new ArgumentException("empty storage key", nameof(key));
            var safe = new StringBuilder(key.Length);
            foreach (var c in key)
                safe.Append(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' ? c : '_');
            var name = safe.ToString();
            if (name.Length > 120 || name.Trim('.').Length == 0 || name != key)
            {
                // Unusual keys: a stable, path-safe name from their hash.
                using (var sha = SHA256.Create())
                    name = "k_" + BitConverter.ToString(sha.ComputeHash(Encoding.UTF8.GetBytes(key))).Replace("-", "").ToLowerInvariant();
            }
            return Path.Combine(_directory, name + ".dat");
        }

        private static class Dpapi
        {
            private const int CRYPTPROTECT_UI_FORBIDDEN = 0x1;

            [StructLayout(LayoutKind.Sequential)]
            private struct DataBlob
            {
                public int cbData;
                public IntPtr pbData;
            }

            [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            private static extern bool CryptProtectData(ref DataBlob pDataIn, string? szDataDescr, ref DataBlob pOptionalEntropy,
                IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DataBlob pDataOut);

            [DllImport("crypt32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            private static extern bool CryptUnprotectData(ref DataBlob pDataIn, IntPtr ppszDataDescr, ref DataBlob pOptionalEntropy,
                IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DataBlob pDataOut);

            [DllImport("kernel32.dll")]
            private static extern IntPtr LocalFree(IntPtr hMem);

            public static byte[] Protect(byte[] data, byte[] entropy) => Run(data, entropy, protect: true);

            public static byte[] Unprotect(byte[] data, byte[] entropy) => Run(data, entropy, protect: false);

            private static byte[] Run(byte[] data, byte[] entropy, bool protect)
            {
                var input = Pin(data, out var inputHandle);
                var extra = Pin(entropy, out var entropyHandle);
                var output = new DataBlob();
                try
                {
                    var ok = protect
                        ? CryptProtectData(ref input, null, ref extra, IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN, ref output)
                        : CryptUnprotectData(ref input, IntPtr.Zero, ref extra, IntPtr.Zero, IntPtr.Zero, CRYPTPROTECT_UI_FORBIDDEN, ref output);
                    if (!ok) throw new CryptographicException("DPAPI failed", new Win32Exception(Marshal.GetLastWin32Error()));
                    var result = new byte[output.cbData];
                    Marshal.Copy(output.pbData, result, 0, output.cbData);
                    return result;
                }
                finally
                {
                    if (output.pbData != IntPtr.Zero)
                    {
                        // Wipe the decrypted copy before giving the memory back.
                        for (var i = 0; i < output.cbData; i++) Marshal.WriteByte(output.pbData, i, 0);
                        LocalFree(output.pbData);
                    }
                    inputHandle.Free();
                    entropyHandle.Free();
                }
            }

            private static DataBlob Pin(byte[] bytes, out GCHandle handle)
            {
                handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
                return new DataBlob { cbData = bytes.Length, pbData = handle.AddrOfPinnedObject() };
            }
        }
    }
}
