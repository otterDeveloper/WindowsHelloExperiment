using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Xml.Linq;
using Windows.Security.Credentials;
using Windows.Security.Cryptography;
using WindowsHelloAPI;


namespace WindowsHelloExperiment
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private async void WindowsHelloButton_Click(object sender, EventArgs e)
        {

            bool supported = await KeyCredentialManager.IsSupportedAsync();
            if (!supported)
            {
                MessageBox.Show("Windows Hello is not supported");
                return;
            }

            var result = await KeyCredentialManager.RequestCreateAsync("WindowsHelloExperiment", KeyCredentialCreationOption.ReplaceExisting);

            if (result.Status == KeyCredentialStatus.Success)
            {

                var credential = result.Credential;
                Windows.Storage.Streams.IBuffer publicKey = credential.RetrievePublicKey();
                var publicKeyHash = credential.GetHashCode();
                var credentialName = credential.Name;
                var attestationResult = await credential.GetAttestationAsync();
                var certificateChainBuffer = attestationResult.CertificateChainBuffer;
                var certificateChain = CryptographicBuffer.EncodeToBase64String(certificateChainBuffer);

                /*
                var signResult = credential.RequestSignAsync(data, KeyCredentialSignatureAlgorithm.RsaPkcs1).GetResults();
                var signatureBuffer = signResult.Signature;
                var signature = CryptographicBuffer.EncodeToBase64String(signatureBuffer);*/

                string detailsMessage
                    = $"Authenticated\nCredential Name: {credentialName}\n" +
                    $"Public Key: {publicKey.GetHashCode()}\n" +
                    $"Public Key Hash: {publicKeyHash}\n" +
                    $"Certificate Chain: {certificateChain}\n" +
                    $"Attestetion Result: {attestationResult.Status}";

                helloDetaills.Text = detailsMessage;
            }
            else
            {
                MessageBox.Show("Enrollment failed");
            }

        }

        private void richTextBox1_TextChanged(object sender, EventArgs e)
        {

        }
        public const string rpId = "WindowsHelloExperiment";

        private async void buttonWebAuthn_Click(object sender, EventArgs e)
        {

            WEBAUTHN_RP_ENTITY_INFORMATION rpEntityInformation = new WEBAUTHN_RP_ENTITY_INFORMATION()
            {
                dwVersion = WebAuthn.WEBAUTHN_RP_ENTITY_INFORMATION_CURRENT_VERSION,
                pwszId = rpId,
                pwszName = "WindowsHelloExperiment",
                pwszIcon = null
            };

            var userId = new byte[11] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11 };
            IntPtr userIdPtr = Marshal.AllocHGlobal(userId.Length * Marshal.SizeOf(typeof(byte)));
            Marshal.Copy(userId, 0, userIdPtr, userId.Length);


            WEBAUTHN_USER_ENTITY_INFORMATION _USER_ENTITY_INFORMATION = new WEBAUTHN_USER_ENTITY_INFORMATION()
            {
                dwVersion = WebAuthn.WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION,
                cbId = (uint)userId.Length,
                pbId = userIdPtr,
                pwszName = "User1",
                pwszDisplayName = "User 1",
                pwszIcon = "https://i.pravatar.cc/128",

            };

            WEBAUTHN_COSE_CREDENTIAL_PARAMETER[] _CREDENTIAL_PARAMETER = {new WEBAUTHN_COSE_CREDENTIAL_PARAMETER()
            {
                dwVersion = WebAuthn.WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
                pwszCredentialType = WebAuthn.WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
                lAlg = WebAuthn.WEBAUTHN_COSE_ALGORITHM_ECDSA_P256_WITH_SHA256
            }, new WEBAUTHN_COSE_CREDENTIAL_PARAMETER()
            {
                dwVersion = WebAuthn.WEBAUTHN_COSE_CREDENTIAL_PARAMETER_CURRENT_VERSION,
                pwszCredentialType = WebAuthn.WEBAUTHN_CREDENTIAL_TYPE_PUBLIC_KEY,
                lAlg = WebAuthn.WEBAUTHN_COSE_ALGORITHM_RSASSA_PKCS1_V1_5_WITH_SHA256
            }};

            IntPtr credentialParametersPtr = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(WEBAUTHN_COSE_CREDENTIAL_PARAMETER)) * _CREDENTIAL_PARAMETER.Length);
            int offset = 0;
            foreach (var item in _CREDENTIAL_PARAMETER)
            {
                Marshal.StructureToPtr(item, IntPtr.Add(credentialParametersPtr, offset), false);
                offset += Marshal.SizeOf(typeof(WEBAUTHN_COSE_CREDENTIAL_PARAMETER));
            }

            WEBAUTHN_COSE_CREDENTIAL_PARAMETERS _COSE_CREDENTIAL_PARAMETERS = new WEBAUTHN_COSE_CREDENTIAL_PARAMETERS()
            {
                cCredentialParameters = (uint)_CREDENTIAL_PARAMETER.Length,
                pCredentialParameters = credentialParametersPtr
            };

            //randombytes 
            using RandomNumberGenerator rng = RandomNumberGenerator.Create();
            var randomClientData = new byte[20];
            rng.GetBytes(randomClientData);
            IntPtr randomClientDataPointer = Marshal.AllocHGlobal(randomClientData.Length * Marshal.SizeOf(typeof(byte)));
            Marshal.Copy(randomClientData, 0, randomClientDataPointer, randomClientData.Length);

            WEBAUTHN_CLIENT_DATA clientData = new WEBAUTHN_CLIENT_DATA()
            {
                dwVersion = WebAuthn.WEBAUTHN_CLIENT_DATA_CURRENT_VERSION,
                cbClientDataJSON = (uint)randomClientData.Length,
                pbClientDataJSON = randomClientDataPointer,
                pwszHashAlgId = WebAuthn.WEBAUTHN_HASH_ALGORITHM_SHA_256

            };


            WEBAUTHN_CREDENTIALS _CREDENTIAL_LIST = new WEBAUTHN_CREDENTIALS()
            {
                cCredentials = 0,
                pCredentials = IntPtr.Zero
            };

            WEBAUTHN_EXTENSION[] _EXTENSIONs = new WEBAUTHN_EXTENSION[1] {
                new WEBAUTHN_EXTENSION()
                {

                }
            };

            WEBAUTHN_EXTENSIONS _EXTENSIONS = new WEBAUTHN_EXTENSIONS()
            {
                cExtensions = 0,
                pExtensions = IntPtr.Zero
            };

            WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS _AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS = new WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS()
            {
                dwVersion = WebAuthn.WEBAUTHN_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS_VERSION_4,
                dwTimeoutMilliseconds = 120000,
                CredentialList = _CREDENTIAL_LIST,
                Extensions = _EXTENSIONS,
                dwAuthenticatorAttachment = WebAuthn.WEBAUTHN_AUTHENTICATOR_ATTACHMENT_ANY,
                bRequireResidentKey = false,
                dwUserVerificationRequirement = WebAuthn.WEBAUTHN_USER_VERIFICATION_REQUIREMENT_PREFERRED,
                dwAttestationConveyancePreference = WebAuthn.WEBAUTHN_ATTESTATION_CONVEYANCE_PREFERENCE_ANY,
                dwFlags = 0,
                pCancellationId = IntPtr.Zero,
                pExcludeCredentialList = IntPtr.Zero,
                dwLargeBlobSupport = WebAuthn.WEBAUTHN_LARGE_BLOB_SUPPORT_REQUIRED,
                bPreferResidentKey = false,
            };

            IntPtr credentialOptionsPtr = Marshal.AllocHGlobal(Marshal.SizeOf(_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS));
            Marshal.StructureToPtr(_AUTHENTICATOR_MAKE_CREDENTIAL_OPTIONS, credentialOptionsPtr, false);
            WEBAUTHN_CREDENTIAL_ATTESTATION _CREDENTIAL_ATTESTATION = new WEBAUTHN_CREDENTIAL_ATTESTATION();
            IntPtr credentialAttestationPtr = Marshal.AllocHGlobal(Marshal.SizeOf(_CREDENTIAL_ATTESTATION));
            Marshal.StructureToPtr(_CREDENTIAL_ATTESTATION, credentialAttestationPtr, false);

            IntPtr handle = this.Handle;
            await Task.Run(() => WebAuthn.WebAuthNAuthenticatorMakeCredential(handle, ref rpEntityInformation, ref _USER_ENTITY_INFORMATION, ref _COSE_CREDENTIAL_PARAMETERS, ref clientData, credentialOptionsPtr, out credentialAttestationPtr));




            if (credentialAttestationPtr != IntPtr.Zero)
            {
                _CREDENTIAL_ATTESTATION = Marshal.PtrToStructure<WEBAUTHN_CREDENTIAL_ATTESTATION>(credentialAttestationPtr);

                //credentialId
                byte[] credentialIdBytes = new byte[_CREDENTIAL_ATTESTATION.cbCredentialId];
                for (int i = 0, cOffset = 0; i< _CREDENTIAL_ATTESTATION.cbCredentialId; i++)
                {
                    IntPtr credentialIdPtr = IntPtr.Add(_CREDENTIAL_ATTESTATION.pbCredentialId, cOffset);
                    credentialIdBytes[i] = Marshal.ReadByte(credentialIdPtr);
                    cOffset += Marshal.SizeOf(typeof(byte));
                }

                string credentialId = Convert.ToBase64String(credentialIdBytes);

                //authenticatorData

                byte[] authenticatorDataBytes = new byte[_CREDENTIAL_ATTESTATION.cbAuthenticatorData];
                for (int i = 0, cOffset = 0; i < _CREDENTIAL_ATTESTATION.cbAuthenticatorData; i++)
                {
                    IntPtr publicKeyPtr = IntPtr.Add(_CREDENTIAL_ATTESTATION.pbAuthenticatorData, cOffset);
                    authenticatorDataBytes[i] = Marshal.ReadByte(publicKeyPtr);
                    cOffset += Marshal.SizeOf(typeof(byte));
                }

                //first 32 bytes is rpIdHash
                byte[] rpIdHash = new byte[32];
                Array.Copy(authenticatorDataBytes, 0, rpIdHash, 0, 32);
                string rpIdHashString = Convert.ToBase64String(rpIdHash);

                //next 1 byte is flags
                byte flags = authenticatorDataBytes[32];
                //byte 0 user is present
                bool userPresent = (flags & 0b00000001) == 0b00000001;
                //byte 1 reserved for future use
                //byte 2 user is verified
                bool userVerified = (flags & 0b00000100) == 0b00000100;
                //byte 3-5 reserved for future use
                //byte 6 attested credential data included
                bool attestedCredentialDataIncluded = (flags & 0b01000000) == 0b01000000;
                //byte 7 extension data included
                bool extensionDataIncluded = (flags & 0b10000000) == 0b10000000;

                //next 4 bytes is sign count
                byte[] signCountBytes = new byte[4];
                Array.Copy(authenticatorDataBytes, 33, signCountBytes, 0, 4);
                uint signCount = BitConverter.ToUInt32(signCountBytes, 0);





                string detailsMessage = $"Version: {WebAuthn.WebAuthNGetApiVersionNumber()}\n" +
                    $"Credential Attestation Version: {_CREDENTIAL_ATTESTATION.dwVersion}\n" +
                $"Credential ID lenght: {_CREDENTIAL_ATTESTATION.cbCredentialId}\n" +
                $"Credential ID: {credentialId}\n" +
                $"Authenticator Data lenght: {_CREDENTIAL_ATTESTATION.cbAuthenticatorData}\n" +
                $"Authenticator Data:\n" +
                $"\tRP ID Hash: {rpIdHashString}\n" +
                $"\tFlags: {flags}\n" +
                $"\t\tUser Present: {userPresent}\n" +
                $"\t\tUser Verified: {userVerified}\n" +
                $"\t\tAttested Credential Data Included: {attestedCredentialDataIncluded}\n" +
                $"\t\tExtension Data Included: {extensionDataIncluded}\n" +
                $"\tSign Count: {signCount}\n" +
                $"Used Transport: {_CREDENTIAL_ATTESTATION.dwUsedTransport}\n" +
                $"Resident Key: {_CREDENTIAL_ATTESTATION.bResidentKey}\n" +
                $"Attestation decode type: {_CREDENTIAL_ATTESTATION.dwAttestationDecodeType}\n" +
                $"Format type: {_CREDENTIAL_ATTESTATION.pwszFormatType}";
                helloDetaills.Text = detailsMessage;
            }

            else
            {
                helloDetaills.Text = "Enrollment failed";
            }

            // clean up
            Marshal.FreeHGlobal(randomClientDataPointer);
            Marshal.FreeHGlobal(userIdPtr);
            Marshal.FreeHGlobal(credentialParametersPtr);
            Marshal.FreeHGlobal(credentialOptionsPtr);
            Marshal.FreeHGlobal(credentialAttestationPtr);

            WebAuthn.WebAuthNFreeCredentialAttestation(credentialAttestationPtr);

            Marshal.FreeHGlobal(credentialAttestationPtr);


        }

        private void buttonListCredentials_Click(object sender, EventArgs e)
        {
            WEBAUTHN_GET_CREDENTIALS_OPTIONS _GET_CREDENTIALS_OPTIONS = new WEBAUTHN_GET_CREDENTIALS_OPTIONS()
            {
                bBrowserInPrivateMode = false,
                dwVersion = WebAuthn.WEBAUTHN_GET_CREDENTIALS_OPTIONS_CURRENT_VERSION,
                pwszRpId = rpId,
            };

            IntPtr webAuthnGetCredentialsOptionsPtr = Marshal.AllocHGlobal(Marshal.SizeOf(_GET_CREDENTIALS_OPTIONS));
            Marshal.StructureToPtr(_GET_CREDENTIALS_OPTIONS, webAuthnGetCredentialsOptionsPtr, false);

            WebAuthn.WebAuthNGetPlatformCredentialList(webAuthnGetCredentialsOptionsPtr, out IntPtr credentialListPtr);

            WEBAUTHN_CREDENTIAL_DETAILS_LIST _CREDENTIAL_LIST = Marshal.PtrToStructure<WEBAUTHN_CREDENTIAL_DETAILS_LIST>(credentialListPtr);




            WEBAUTHN_CREDENTIAL_DETAILS[] credentialList = new WEBAUTHN_CREDENTIAL_DETAILS[_CREDENTIAL_LIST.cCredentialDetails];


            for (int i = 0, offset = 0; i < _CREDENTIAL_LIST.cCredentialDetails; i++)
            {
                IntPtr credentialDetailsPtr = IntPtr.Add(_CREDENTIAL_LIST.ppCredentialDetails, offset);
                credentialList[i] = Marshal.PtrToStructure<WEBAUTHN_CREDENTIAL_DETAILS>(credentialDetailsPtr);
                offset += Marshal.SizeOf(typeof(WEBAUTHN_CREDENTIAL_DETAILS));
            }

            string details = "";
            foreach (var credential in credentialList)
            {
                WEBAUTHN_USER_ENTITY_INFORMATION _USER_ENTITY_INFORMATION = Marshal.PtrToStructure<WEBAUTHN_USER_ENTITY_INFORMATION>(credential.pUserInformation);
                details += $"User: ${_USER_ENTITY_INFORMATION.pwszName}";


            }


            //clean up
            Marshal.FreeHGlobal(webAuthnGetCredentialsOptionsPtr);
            Marshal.FreeHGlobal(credentialListPtr);
            WebAuthn.WebAuthNFreePlatformCredentialList(credentialListPtr);
        }
    }
}