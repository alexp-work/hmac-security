namespace Security.HMAC
{
    using System.Linq;
    using System.Net;
    using System.Net.Http;
    using System.Security;
    using System.Text;
    using System.Threading;
    using System.Threading.Tasks;

    public sealed class HMACHandler : DelegatingHandler
    {
        private readonly IAppSecretRepository appSecretRepository;
        private readonly ISigningAlgorithm signingAlgorithm;

        public HMACHandler(
            IAppSecretRepository appSecretRepository,
            ISigningAlgorithm signingAlgorithm)
        {
            this.appSecretRepository = appSecretRepository;
            this.signingAlgorithm = signingAlgorithm;
        }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            var req = request;
            var h = req.Headers;

            var appId = h.GetValues(Headers.XAppId).First();
            var authSchema = h.Authorization?.Scheme;
            var authValue = h.Authorization?.Parameter;

            if (appId != null && authSchema == Schemas.HMAC && authValue != null)
            {
                var builder = new CannonicalRepresentationBuilder();
                var content = builder.BuildRepresentation(
                    h.GetValues(Headers.XNonce).FirstOrDefault(),
                    appId,
                    req.Method.Method,
                    req.Content.Headers.ContentType.MediaType,
                    Encoding.UTF8.GetString(req.Content.Headers.ContentMD5),
                    req.RequestUri);

                SecureString secret;
                if (content != null && (secret = appSecretRepository.GetSecret(appId)) != null)
                {
                    var signature = signingAlgorithm.Sign(secret, content);
                    if (authValue == signature)
                    {
                        return await base.SendAsync(request, cancellationToken);
                    }
                }
            }

            return new HttpResponseMessage(HttpStatusCode.Unauthorized)
            {
                Headers =
                {
                    { Headers.WWWAuthenticate, Schemas.HMAC }
                }
            };
        }
    }
}