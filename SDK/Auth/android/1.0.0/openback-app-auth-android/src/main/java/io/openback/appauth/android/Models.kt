package io.openback.appauth.android

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonPrimitive

/**
 * A user of the pool as the user sees themselves. `GET /me` adds [orgId], [roles], [providers] and [hasPassword].
 */
@Serializable
public data class PoolUser(
    val id: String,
    val email: String? = null,
    @SerialName("email_verified") val emailVerified: Boolean = false,
    @SerialName("display_name") val displayName: String? = null,
    @SerialName("photo_url") val photoUrl: String? = null,
    /** "it", "en" or null. */
    val locale: String? = null,
    val attributes: JsonObject = JsonObject(emptyMap()),
    /** A guest account (`signInAnonymously`). */
    val anonymous: Boolean = false,
    @SerialName("created_at") val createdAt: String? = null,
    @SerialName("last_login_at") val lastLoginAt: String? = null,
    val mfa: JsonObject? = null,
    @SerialName("org_id") val orgId: String? = null,
    val roles: List<String> = emptyList(),
    val providers: List<LinkedProvider> = emptyList(),
    @SerialName("has_password") val hasPassword: Boolean? = null,
) {
    /** True when two-step verification (TOTP) is on. */
    val isTotpEnabled: Boolean
        get() = mfa?.get("totp")?.jsonPrimitive?.booleanOrNull == true
}

/** A sign-in provider linked to the user. */
@Serializable
public data class LinkedProvider(
    @SerialName("provider_id") val providerId: String? = null,
    val kind: String? = null,
)

/** The organization a session is signed in to (B2B pools; null in B2C pools). */
@Serializable
public data class ActiveOrg(
    val id: String,
    val name: String? = null,
    val roles: List<String> = emptyList(),
    /** How many organizations the user could sign in to. */
    val choices: Int = 0,
)

/** An organization of the user. */
@Serializable
public data class Organization(
    val id: String,
    val name: String? = null,
    val roles: List<String> = emptyList(),
    val disabled: Boolean = false,
)

/** `GET /orgs`: the user's organizations and the active one (B2C: empty). */
@Serializable
public data class OrganizationList(
    val orgs: List<Organization> = emptyList(),
    val active: String? = null,
)

/** A member of an organization. */
@Serializable
public data class Member(
    @SerialName("user_id") val userId: String,
    val email: String? = null,
    @SerialName("display_name") val displayName: String? = null,
    val disabled: Boolean = false,
    val roles: List<String> = emptyList(),
    @SerialName("created_at") val createdAt: String? = null,
)

/** An organization role. */
@Serializable
public data class OrgRole(val key: String, val label: String? = null)

/** A page of members and the roles that can be granted. */
@Serializable
public data class MemberPage(
    val items: List<Member> = emptyList(),
    val total: Int? = null,
    val roles: List<OrgRole> = emptyList(),
)

/** A two-step verification enrollment: show [otpauthUri] as a QR code (or [secret]), then confirm a code. */
@Serializable
public data class MfaEnrollment(
    val secret: String,
    @SerialName("otpauth_uri") val otpauthUri: String,
) {
    override fun toString(): String = "MfaEnrollment(***)"
}

/** The recovery codes of a confirmed enrollment (show them once) and, during a sign-in, its outcome. */
public data class MfaConfirmation(val recoveryCodes: List<String>, val outcome: AuthOutcome?)

/** The signed-in state, as [OpenBackAuth.authState]. */
public sealed class AuthState {
    /** No session. */
    public object SignedOut : AuthState() {
        override fun toString(): String = "SignedOut"
    }

    /** A session; [user] is null only between a hosted sign-in's code exchange and its `GET /me`. */
    public data class SignedIn(val user: PoolUser?, val org: ActiveOrg?) : AuthState()
}

/**
 * The outcome of a sign-up or sign-in step. Only [SignedIn] keeps a session; the others tell the app how to continue.
 * [details] is the answer without the tokens.
 */
public sealed class AuthOutcome {
    public abstract val status: String
    public abstract val details: JsonObject

    /** `ok`: signed in. [recoveryCodes] after an enrollment confirmed during the sign-in. */
    public data class SignedIn(
        val user: PoolUser?,
        val org: ActiveOrg?,
        val recoveryCodes: List<String>,
        override val details: JsonObject,
    ) : AuthOutcome() {
        override val status: String get() = "ok"
    }

    /** `verification_required`: the email address must be verified first. */
    public data class VerificationRequired(override val details: JsonObject) : AuthOutcome() {
        override val status: String get() = "verification_required"
    }

    /** `mfa_required`: ask the authenticator code, then [OpenBackAuth.verifyMfa]. */
    public data class MfaRequired(val mfaToken: String, override val details: JsonObject) : AuthOutcome() {
        override val status: String get() = "mfa_required"
    }

    /** `mfa_enroll_required`: [OpenBackAuth.enrollMfa] then [OpenBackAuth.confirmMfa] with [mfaToken]. */
    public data class MfaEnrollRequired(val mfaToken: String, override val details: JsonObject) : AuthOutcome() {
        override val status: String get() = "mfa_enroll_required"
    }

    /** `password_change_required`: [OpenBackAuth.changeForcedPassword] with [changeToken]. */
    public data class PasswordChangeRequired(val changeToken: String, override val details: JsonObject) : AuthOutcome() {
        override val status: String get() = "password_change_required"
    }

    /** A status this version of the SDK does not know. */
    public data class Unknown(override val status: String, override val details: JsonObject) : AuthOutcome()
}
