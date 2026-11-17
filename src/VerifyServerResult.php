<?php

namespace AltchaOrg\Altcha;

class VerifyServerResult
{
    /**
     * @param bool                                 $verified         Whether Sentinel verified the payload.
     * @param null|string                          $apiKey           The payload's API key id.
     * @param null|string                          $reason           Why verification failed: Sentinel's `reason`
     *                                                               (e.g. `PAYLOAD_ALREADY_USED`), the `code` of an
     *                                                               error response (e.g. `API_KEY_REQUIRED`), its
     *                                                               `error`, `HTTP_<status>` or a network error message.
     * @param null|ServerSignatureVerificationData $verificationData Verification data returned by Sentinel, with
     *                                                               Sentinel v2's nested objects flattened to the
     *                                                               signed dotted keys (`device.browser`).
     */
    public function __construct(
        public readonly bool $verified,
        public readonly ?string $apiKey = null,
        public readonly ?string $reason = null,
        public readonly ?ServerSignatureVerificationData $verificationData = null,
    ) {
    }

    /**
     * @param array<string, mixed> $arr
     */
    public static function fromArray(array $arr): self
    {
        /** @var null|array<string, mixed> $verificationData */
        $verificationData = isset($arr['verificationData']) && \is_array($arr['verificationData']) ? $arr['verificationData'] : null;

        return new self(
            verified: isset($arr['verified']) && \is_bool($arr['verified']) && $arr['verified'],
            apiKey: isset($arr['apiKey']) && \is_string($arr['apiKey']) ? $arr['apiKey'] : null,
            reason: isset($arr['reason']) && \is_string($arr['reason']) ? $arr['reason'] : null,
            verificationData: null !== $verificationData ? new ServerSignatureVerificationData(self::flatten($verificationData)) : null,
        );
    }

    /**
     * Sentinel v2 nests `verificationData` on dots (`{"device": {"browser": …}}`); flattens it
     * back to the signed keys (`device.browser`). Lists (`fields`, `reasons`) stay arrays, and
     * already-flat data (a v1 Sentinel) is returned unchanged.
     *
     * @param array<mixed> $data
     *
     * @return array<string, mixed>
     */
    private static function flatten(array $data, string $prefix = ''): array
    {
        $result = [];
        foreach ($data as $key => $value) {
            $path = '' === $prefix ? (string) $key : $prefix . '.' . $key;
            if (\is_array($value) && [] !== $value && !array_is_list($value)) {
                foreach (self::flatten($value, $path) as $nestedPath => $nestedValue) {
                    $result[$nestedPath] = $nestedValue;
                }
            } else {
                $result[$path] = $value;
            }
        }

        return $result;
    }
}
