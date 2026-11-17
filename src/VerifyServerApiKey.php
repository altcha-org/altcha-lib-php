<?php

namespace AltchaOrg\Altcha;

/**
 * Credentials for Sentinel v2's `/v2/verify/signature`: a `restricted` or `full` API key
 * of the account that owns the payload's API key, sent as HTTP Basic `id:secret`.
 */
class VerifyServerApiKey
{
    /**
     * @param string $id     API key id (`key_…`).
     * @param string $secret API key secret (`sec_…`).
     */
    public function __construct(
        public readonly string $id,
        public readonly string $secret,
    ) {
    }
}
