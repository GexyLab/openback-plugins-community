<?php

declare(strict_types=1);

// Bundled copy of openback-app-auth-php 1.0.0 (MIT), namespace prefixed for this plugin.

namespace OpenBackAppAuthWp\Sdk;

/** The `status` of a sign-up / sign-in answer. */
enum OutcomeStatus: string
{
    /** Signed in: the session is kept. */
    case Ok = 'ok';
    /** The email address must be verified first (a code or link was sent). */
    case VerificationRequired = 'verification_required';
    /** Second factor needed: continue with Client::verifyMfa($outcome->mfaToken, $code). */
    case MfaRequired = 'mfa_required';
    /** The pool requires two factors and the user has none: Client::enrollMfa($outcome->mfaToken), then confirmMfa(). */
    case MfaEnrollRequired = 'mfa_enroll_required';
    /** The password must be changed: Client::changeForcedPassword($outcome->changeToken, $newPassword). */
    case PasswordChangeRequired = 'password_change_required';
    /** A status this SDK version does not know (see Outcome::$rawStatus). */
    case Unknown = 'unknown';
}
