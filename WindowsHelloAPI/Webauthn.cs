using System;
using System.Runtime.InteropServices;

namespace WindowsHelloAPI
{
    public static class WebAuthn
    {
        public const int WEBAUTHN_API_VERSION_1 = 1;
        public const int WEBAUTHN_API_VERSION_2 = 2;
        public const int WEBAUTHN_API_VERSION_3 = 3;
        public const int WEBAUTHN_API_VERSION_4 = 4;
        public const int WEBAUTHN_API_VERSION_5 = 5;
        public const int WEBAUTHN_API_VERSION_6 = 6;
        public const int WEBAUTHN_API_VERSION_7 = 7;
        public const int WEBAUTHN_API_CURRENT_VERSION = WEBAUTHN_API_VERSION_7;

        public const int WEBAUTHN_CTAP_TRANSPORT_USB = 0x00000001;
        public const int WEBAUTHN_CTAP_TRANSPORT_NFC = 0x00000002;
        public const int WEBAUTHN_CTAP_TRANSPORT_BLE = 0x00000004;
        public const int WEBAUTHN_CTAP_TRANSPORT_TEST = 0x00000008;
        public const int WEBAUTHN_CTAP_TRANSPORT_INTERNAL = 0x00000010;
        public const int WEBAUTHN_CTAP_TRANSPORT_HYBRID = 0x00000020;
        public const int WEBAUTHN_CTAP_TRANSPORT_FLAGS_MASK = 0x0000003F;

        public const string WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY = "public-key";

        public const int WEBAUTHN_CLIENT_DATA_CURRENT_VERSION = 1;

        public const int WEBAUTHN_CREDENTIAL_CURRENT_VERSION = 1;

        public const int WEBAUTHN_CREDENTIAL_EX_CURRENT_VERSION = 1;

        public const int WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION = 1;

        public const int WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION = 1;

        public const int WEBAUTHN_ASSERTION_VERSION_1 = 1;
        public const int WEBAUTHN_ASSERTION_VERSION_2 = 2;
        public const int WEBAUTHN_ASSERTION_VERSION_3 = 3;
        public const int WEBAUTHN_ASSERTION_VERSION_4 = 4;
        public const int WEBAUTHN_ASSERTION_VERSION_5 = 5;
        public const int WEBAUTHN_ASSERTION_CURRENT_VERSION = WEBAUTHN_ASSERTION_VERSION_5;

        public const int WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_1 = 1;
        public const int WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_2 = 2;
        public const int WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_3 = 3;
        public const int WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_4 = 4;
        public const int WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_5 = 5;
        public const int WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_6 = 6;
        public const int WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_7 = 7;
        public const int WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_CURRENT_VERSION = WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_7;

        public const int WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_1 = 1;
        public const int WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_2 = 2;
        public const int WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_3 = 3;
        public const int WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_4 = 4;
        public const int WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_5 = 5;
        public const int WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_6 = 6;
        public const int WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_7 = 7;
        public const int WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_CURRENT_VERSION = WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS_VERSION_7;

        public const int WEBAUTHN_ATTESTATION_DECODE_NONE = 0;
        public const int WEBAUTHN_ATTESTATION_DECODE_COMMON = 1;

        public const string WEBAUTHN_HASH_ALGORITHM_SHA_256 = "SHA-256";
        public const string WEBAUTHN_HASH_ALGORITHM_SHA_384 = "SHA-384";
        public const string WEBAUTHN_HASH_ALGORITHM_SHA_512 = "SHA-512";

        public const string WEBAUTHN_EXTENSIONS_IDENTIFIER_HMAC_SECRET = "hmac-secret";
        public const string WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_PROTECT = "credProtect";
        public const string WEBAUTHN_EXTENSIONS_IDENTIFIER_CRED_BLOB = "credBlob";
        public const string WEBAUTHN_EXTENSIONS_IDENTIFIER_MIN_PIN_LENGTH = "minPinLength";

        public const int NTE_NOT_SUPPORTED = unchecked((int)0x80090029);
        public const int NTE_INVALID_PARAMETER = unchecked((int)0x80090027);
        public const int NTE_DEVICE_NOT_FOUND = unchecked((int)0x80090035);
        public const int NTE_NOT_FOUND = unchecked((int)0x80090011);
        public const int NTE_EXISTS = unchecked((int)0x8009000F);
        public const int NTE_USER_CANCELLED = unchecked((int)0x80090036);
        public const int NTE_TOKEN_KEYSET_STORAGE_FULL = unchecked((int)0x80090027);
        public const int E_INVALIDARG = unchecked((int)0x80070057);

        public const int ERROR_NOT_SUPPORTED = 50;
        public const int ERROR_CANCELLED = 1223;
        public const int ERROR_TIMEOUT = 1460;

      

      

        public const int WEBAUTHN_HASH_ALGORITHM_SHA256 = 0;
        public const int WEBAUTHN_HASH_ALGORITHM_SHA384 = 1;
        public const int WEBAUTHN_HASH_ALGORITHM_SHA512 = 2;

      

        public const int WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256 = -7;
        public const int WEBAUTHN_COSE_ALGORITHM_ECDSA_P384_WITH_SHA384 = -35;
        public const int WEBAUTHN_COSE_ALGORITHM_ECDSA_P521_WITH_SHA512 = -36;

        public const int WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA256 = -257;
        public const int WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA384 = -258;
        public const int WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA512 = -259;

        public const int WEBAUTHN_COSE_ALGORITHM_RSA_PSS_WITH_SHA256 = -37;
        public const int WEBAUTHN_COSE_ALGORITHM_RSA_PSS_WITH_SHA384 = -38;
        public const int WEBAUTHN_COSE_ALGORITHM_RSA_PSS_WITH_SHA512 = -39;

       
        public const int WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION = 1;
        
        public const int WEBAUTHN_COMMON_ATTESTATION_CURRENT_VERSION = 1;
        

        public const int WEBAUTHN_CRED_LARGE_BLOB_OPERATION_NONE = 0;
        public const int WEBAUTHN_CRED_LARGE_BLOB_OPERATION_GET = 1;
        public const int WEBAUTHN_CRED_LARGE_BLOB_OPERATION_SET = 2;
        public const int WEBAUTHN_CRED_LARGE_BLOB_OPERATION_DELETE = 3;

        
        public const int WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY = 0;
        public const int WEBAUTHN_AUTHENTICATOR_ATTACHMENT_PLATFORM = 1;
        public const int WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM = 2;
        public const int WEBAUTHN_AUTHENTICATOR_ATTACHMENT_CROSS_PLATFORM_U2F_V2 = 3;

        public const int WEBAUTHN_USER_VERIFICATION_REQUIREMENT_ANY = 0;
        public const int WEBAUTHN_USER_VERIFICATION_REQUIREMENT_REQUIRED = 1;
        public const int WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED = 2;
        public const int WEBAUTHN_USER_VERIFICATION_REQUIREMENT_DISCOURAGED = 3;

        public const int WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_ANY = 0;
        public const int WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_NONE = 1;
        public const int WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_INDIRECT = 2;
        public const int WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_DIRECT = 3;

        public const int WEBAUTHN_ENTERPRISE_ATTESTATION_NONE = 0;
        public const int WEBAUTHN_ENTERPRISE_ATTESTATION_VENDOR_FACILITATED = 1;
        public const int WEBAUTHN_ENTERPRISE_ATTESTATION_PLATFORM_MANAGED = 2;

        public const int WEBAUTHN_LARGE_BLOB_SUPPORT_NONE = 0;
        public const int WEBAUTHN_LARGE_BLOB_SUPPORT_REQUIRED = 1;
        public const int WEBAUTHN_LARGE_BLOB_SUPPORT_PREFERRED = 2;

        public const int WEBAUTHN_CRED_LARGE_BLOB_STATUS_NONE = 0;
        public const int WEBAUTHN_CRED_LARGE_BLOB_STATUS_SUCCESS = 1;
        public const int WEBAUTHN_CRED_LARGE_BLOB_STATUS_NOT_SUPPORTED = 2;
        public const int WEBAUTHN_CRED_LARGE_BLOB_STATUS_INVALID_DATA = 3;
        public const int WEBAUTHN_CRED_LARGE_BLOB_STATUS_INVALID_PARAMETER = 4;
        public const int WEBAUTHN_CRED_LARGE_BLOB_STATUS_NOT_FOUND = 5;
        public const int WEBAUTHN_CRED_LARGE_BLOB_STATUS_MULTIPLE_CREDENTIALS = 6;
        public const int WEBAUTHN_CRED_LARGE_BLOB_STATUS_LACK_OF_SPACE = 7;
        public const int WEBAUTHN_CRED_LARGE_BLOB_STATUS_PLATFORM_ERROR = 8;
        public const int WEBAUTHN_CRED_LARGE_BLOB_STATUS_AUTHENTICATOR_ERROR = 9;

        public const int CTAPCBOR_HYBRID_STORAGE_LINKED_DATA_VERSION_1 = 1;
        public const int CTAPCBOR_HYBRID_STORAGE_LINKED_DATA_CURRENT_VERSION = CTAPCBOR_HYBRID_STORAGE_LINKED_DATA_VERSION_1;

        public const int WEBAUTHN_CREDENTIAL_DETAILS_VERSION_1 = 1;
        public const int WEBAUTHN_CREDENTIAL_DETAILS_VERSION_2 = 2;
        public const int WEBAUTHN_CREDENTIAL_DETAILS_CURRENT_VERSION = WEBAUTHN_CREDENTIAL_DETAILS_VERSION_2;

        public const int WEBAUTHN_GET_CREDENTIALS_OPTIONS_VERSION_1 = 1;
        public const int WEBAUTHN_GET_CREDENTIALS_OPTIONS_CURRENT_VERSION = WEBAUTHN_GET_CREDENTIALS_OPTIONS_VERSION_1;

        public const int WEBAUTHN_CTAP_ONE_HMAC_SECRET_LENGTH = 32;

        public const int WEBAUTHN_AUTHENTICATOR_HMAC_SECRET_VALUES_FLAG = 0x00100000;

        public const string WEBAUTHN_ATTESTATION_TYPE_PACKED = "packed";
        public const string WEBAUTHN_ATTESTATION_TYPE_U2F = "fido-u2f";
        public const string WEBAUTHN_ATTESTATION_TYPE_TPM = "tpm";
        public const string WEBAUTHN_ATTESTATION_TYPE_NONE = "none";

        public const int WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_1 = 1;
        public const int WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_2 = 2;
        public const int WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_3 = 3;
        public const int WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_4 = 4;
        public const int WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_5 = 5;
        public const int WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_6 = 6;
        public const int WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION = WEBAUTHN_CREDENTIAL_ATTESTATION_VERSION_6;
        
        
        [DllImport("webauthn.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern uint WebAuthNGetApiVersionNumber();

        [DllImport("webauthn.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern int WebAuthNIsUserVerifyingPlatformAuthenticatorAvailable(out bool isUserVerifyingPlatformAuthenticatorAvailable);

        [DllImport("webauthn.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern int WebAuthNAuthenticatorMakeCredential(
            IntPtr hWnd,
            ref WEBAUTHN_RP_ENTITY_INFORMATION rpInformation,
            ref WEBAUTHN_USER_ENTITY_INFORMATION userInformation,
            ref WEBAUTHN_COSE_CREDENTIAL_PARAMETERS pubKeyCredParams,
            ref WEBAUTHN_CLIENT_DATA webAuthNClientData,
            IntPtr webAuthNMakeCredentialOptions,
            out IntPtr webAuthNCredentialAttestation);

        [DllImport("webauthn.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern int WebAuthNAuthenticatorGetAssertion(
            IntPtr hWnd,
            string rpId,
            ref WEBAUTHN_CLIENT_DATA webAuthNClientData,
            IntPtr webAuthNGetAssertionOptions,
            out IntPtr webAuthNAssertion);

        [DllImport("webauthn.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern void WebAuthNFreeCredentialAttestation(IntPtr webAuthNCredentialAttestation);

        [DllImport("webauthn.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern void WebAuthNFreeAssertion(IntPtr webAuthNAssertion);

        [DllImport("webauthn.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern int WebAuthNGetCancellationId(out Guid cancellationId);

        [DllImport("webauthn.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern int WebAuthNCancelCurrentOperation(ref Guid cancellationId);

        [DllImport("webauthn.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern int WebAuthNGetPlatformCredentialList(IntPtr getCredentialsOptions, out IntPtr credentialDetailsList);

        [DllImport("webauthn.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern void WebAuthNFreePlatformCredentialList(IntPtr credentialDetailsList);

        [DllImport("webauthn.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern int WebAuthNDeletePlatformCredential(uint cbCredentialId, byte[] pbCredentialId);

        [DllImport("webauthn.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern IntPtr WebAuthNGetErrorName(int hr);

        [DllImport("webauthn.dll", CallingConvention = CallingConvention.StdCall)]
        public static extern int WebAuthNGetW3CExceptionDOMError(int hr);
    }



    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_RP_ENTITY_INFORMATION
    {
        public uint dwVersion;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszId;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszName;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? pwszIcon;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_USER_ENTITY_INFORMATION
    {
        public uint dwVersion;
        public uint cbId;
        public IntPtr pbId;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszName;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? pwszIcon;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszDisplayName;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_CLIENT_DATA
    {
        public uint dwVersion;
        public uint cbClientDataJSON;
        public IntPtr pbClientDataJSON;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszHashAlgId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_COSE_CREDENTIAL_PARAMETER
    {
        public uint dwVersion;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszCredentialType;
        public int lAlg;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_COSE_CREDENTIAL_PARAMETERS
    {
        public uint cCredentialParameters;
        public IntPtr pCredentialParameters;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_CREDENTIAL
    {
        public uint dwVersion;
        public uint cbId;
        public IntPtr pbId;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszCredentialType;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_CREDENTIALS
    {
        public uint cCredentials;
        public IntPtr pCredentials;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_CREDENTIAL_EX
    {
        public uint dwVersion;
        public uint cbId;
        public IntPtr pbId;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszCredentialType;
        public uint dwTransports;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_CREDENTIAL_LIST
    {
        public uint cCredentials;
        public IntPtr ppCredentials;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CTAPCBOR_HYBRID_STORAGE_LINKED_DATA
    {
        public uint dwVersion;
        public uint cbContactId;
        public IntPtr pbContactId;
        public uint cbLinkId;
        public IntPtr pbLinkId;
        public uint cbLinkSecret;
        public IntPtr pbLinkSecret;
        public uint cbPublicKey;
        public IntPtr pbPublicKey;
        public string pwszAuthenticatorName;
        public ushort wEncodedTunnelServerDomain;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_CREDENTIAL_DETAILS
    {
        public uint dwVersion;
        public uint cbCredentialID;
        public IntPtr pbCredentialID;
        public IntPtr pRpInformation;
        public IntPtr pUserInformation;
        public int bRemovable;
        public int bBackedUp;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_CREDENTIAL_DETAILS_LIST
    {
        public uint cCredentialDetails;
        public IntPtr ppCredentialDetails;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_GET_CREDENTIALS_OPTIONS
    {
        public uint dwVersion;
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszRpId;
        public bool bBrowserInPrivateMode;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_HMAC_SECRET_SALT
    {
        // Size of pbFirst.
        public uint cbFirst;
        public IntPtr pbFirst;
        // Size of pbSecond.
        public uint cbSecond;
        public IntPtr pbSecond;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_CRED_WITH_HMAC_SECRET_SALT
    {
        // Size of pbCredID.
        public uint cbCredID;
        public IntPtr pbCredID;
        // PRF Values for above credential
        public IntPtr pHmacSecretSalt;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_HMAC_SECRET_SALT_VALUES
    {
        public IntPtr pGlobalHmacSalt;
        public uint cCredWithHmacSecretSaltList;
        public IntPtr pCredWithHmacSecretSaltList;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_CRED_PROTECT_EXTENSION_IN
    {
        public uint dwCredProtect;
        public bool bRequireCredProtect;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_CRED_BLOB_EXTENSION
    {
        public uint cbCredBlob;
        public IntPtr pbCredBlob;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_EXTENSION
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string pwszExtensionIdentifier;
        public uint cbExtension;
        public IntPtr pvExtension;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_EXTENSIONS
    {
        public uint cExtensions;
        public IntPtr pExtensions;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS
    {
        public uint dwVersion;
        public uint dwTimeoutMilliseconds;
        public WEBAUTHN_CREDENTIALS CredentialList;
        public WEBAUTHN_EXTENSIONS Extensions;
        public uint dwAuthenticatorAttachment;
        public bool bRequireResidentKey;
        public uint dwUserVerificationRequirement;
        public uint dwAttestationConveyancePreference;
        public uint dwFlags;
        public IntPtr pCancellationId;
        public IntPtr pExcludeCredentialList;
        public uint dwEnterpriseAttestation;
        public uint dwLargeBlobSupport;
        public bool bPreferResidentKey;
        public int bBrowserInPrivateMode;
        public int bEnablePrf;
        public IntPtr pLinkedDevice;
        public uint cbJsonExt;
        public IntPtr pbJsonExt;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_AUTHENTICATOR_GET_ASSERTION_OPTIONS
    {
        public uint dwVersion;
        public uint dwTimeoutMilliseconds;
        public WEBAUTHN_CREDENTIALS CredentialList;
        public WEBAUTHN_EXTENSIONS Extensions;
        public uint dwAuthenticatorAttachment;
        public uint dwUserVerificationRequirement;
        public uint dwFlags;
        public string pwszU2fAppId;
        public IntPtr pbU2fAppId;
        public IntPtr pCancellationId;
        public IntPtr pAllowCredentialList;
        public uint dwCredLargeBlobOperation;
        public uint cbCredLargeBlob;
        public IntPtr pbCredLargeBlob;
        public IntPtr pHmacSecretSaltValues;
        public bool bBrowserInPrivateMode;
        public IntPtr pLinkedDevice;
        public int bAutoFill;
        public uint cbJsonExt;
        public IntPtr pbJsonExt;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_COMMON_ATTESTATION
    {
        public uint dwVersion;
        public string pwszAlg;
        public int lAlg;
        public uint cbSignature;
        public IntPtr pbSignature;
        public uint cX5c;
        public IntPtr pX5c;
        public string pwszVer;
        public uint cbCertInfo;
        public IntPtr pbCertInfo;
        public uint cbPubArea;
        public IntPtr pbPubArea;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_CREDENTIAL_ATTESTATION
    {
        public uint dwVersion;
        public string pwszFormatType;
        public uint cbAuthenticatorData;
        public IntPtr pbAuthenticatorData;
        public uint cbAttestation;
        public IntPtr pbAttestation;
        public uint dwAttestationDecodeType;
        public IntPtr pvAttestationDecode;
        public uint cbAttestationObject;
        public IntPtr pbAttestationObject;
        public uint cbCredentialId;
        public IntPtr pbCredentialId;
        public WEBAUTHN_EXTENSIONS Extensions;
        public uint dwUsedTransport;
        public bool bEpAtt;
        public bool bLargeBlobSupported;
        public bool bResidentKey;
        public bool bPrfEnabled;
        public uint cbUnsignedExtensionOutputs;
        public IntPtr pbUnsignedExtensionOutputs;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct WEBAUTHN_ASSERTION
    {
        public uint dwVersion;
        public uint cbAuthenticatorData;
        public IntPtr pbAuthenticatorData;
        public uint cbSignature;
        public IntPtr pbSignature;
        public WEBAUTHN_CREDENTIAL Credential;
        public uint cbUserId;
        public IntPtr pbUserId;
        public WEBAUTHN_EXTENSIONS Extensions;
        public uint cbCredLargeBlob;
        public IntPtr pbCredLargeBlob;
        public uint dwCredLargeBlobStatus;
        public IntPtr pHmacSecret;
        public uint dwUsedTransport;
        public uint cbUnsignedExtensionOutputs;
        public IntPtr pbUnsignedExtensionOutputs;
    }


}