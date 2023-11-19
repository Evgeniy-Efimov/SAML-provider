namespace Domain.Models
{
    public class SAMLParameters
    {
        public bool IsEnableSaml { get; set; }
        public string ClientMetadataPath { get; set; }
        public string EntityId { get; set; }
        public string IdpAuthEndpoint { get; set; }
        public string IdpLogoutEndpoint { get; set; }
        public string RedirectUrl { get; set; }
        public string IdpCerPath { get; set; }
        public string RelayState { get; set; }
        public string ProviderName { get; set; }
        public string AssertionConsumerService { get; set; }
        public string SpPfxPath { get; set; }
        public string SpPfxPassword { get; set; }
        public string RequestSignatureCanonicalizationMethod { get; set; }
        public string RequestSignatureMethod { get; set; }
        public string NameIDFormat { get; set; }
        public string LoginAttributeName { get; set; }
        public bool IsLogSamlResponse { get; set; }
        public bool IsLogSamlRequest { get; set; }
        public bool IsSignSSORequest { get; set; }
        public bool IsSignSLORequest { get; set; }
        public bool IsEnableSLO { get; set; }
    }
}
