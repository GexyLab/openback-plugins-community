using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using Xunit;

namespace OpenBack.AppAuth.Tests
{
    public class StorageTests
    {
        [Fact]
        public async Task In_memory_storage_round_trip()
        {
            var s = new InMemoryTokenStorage();
            Assert.Null(await s.GetAsync("k"));
            await s.SetAsync("k", "v");
            Assert.Equal("v", await s.GetAsync("k"));
            await s.RemoveAsync("k");
            Assert.Null(await s.GetAsync("k"));
        }

        [Fact]
        public async Task Dpapi_file_storage_encrypts_at_rest()
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return;   // Windows only
            var dir = Path.Combine(Path.GetTempPath(), "openback-appauth-test-" + Guid.NewGuid().ToString("N"));
            try
            {
                var s = new ProtectedFileTokenStorage(dir);
                const string key = "openback.auth.uapp_test";
                const string secret = "{\"refreshToken\":\"obur_secret_value\"}";
                await s.SetAsync(key, secret);
                await s.SetAsync(key, secret);   // replace
                Assert.Equal(secret, await s.GetAsync(key));
                var files = Directory.GetFiles(dir);
                Assert.Single(files);
                Assert.DoesNotContain("obur_secret_value", Encoding.UTF8.GetString(File.ReadAllBytes(files[0])));

                // Another entropy cannot read it: as if missing.
                Assert.Null(await new ProtectedFileTokenStorage(dir, Encoding.UTF8.GetBytes("other")).GetAsync(key));

                await s.SetAsync("weird/key:..", "x");
                Assert.Equal("x", await s.GetAsync("weird/key:.."));
                Assert.All(Directory.GetFiles(dir), f => Assert.Equal(dir, Path.GetDirectoryName(f)));

                await s.RemoveAsync(key);
                Assert.Null(await s.GetAsync(key));
            }
            finally
            {
                if (Directory.Exists(dir)) Directory.Delete(dir, true);
            }
        }
    }
}
