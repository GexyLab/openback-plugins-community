using System.Text.Json.Serialization;

namespace OpenBack.AppAuth
{
    /// <summary>The persisted session: <c>{accessToken, refreshToken, idToken, expiresAt (epoch ms), user, org}</c>
    /// (the same JSON as the other OpenBack App Auth SDKs). Treated as immutable: changes make a copy.</summary>
    internal sealed class StoredSession
    {
        [JsonPropertyName("accessToken")] public string? AccessToken { get; set; }
        [JsonPropertyName("refreshToken")] public string? RefreshToken { get; set; }
        [JsonPropertyName("idToken")] public string? IdToken { get; set; }
        [JsonPropertyName("expiresAt")] public long ExpiresAt { get; set; }
        [JsonPropertyName("user")] public PoolUser? User { get; set; }
        [JsonPropertyName("org")] public ActiveOrg? Org { get; set; }

        public StoredSession WithUser(PoolUser? user)
        {
            var copy = (StoredSession)MemberwiseClone();
            copy.User = user;
            return copy;
        }

        public override string ToString() => "StoredSession(***)";
    }
}
