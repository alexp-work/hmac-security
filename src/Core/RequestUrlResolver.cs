using System;

namespace Security.HMAC
{
    public interface IRequestUrlResolver
    {
        Uri Resolve(HmacRequestInfo msg);
    }

    public class RequestUrlResolver : IRequestUrlResolver
    {
        private readonly string overrideScheme;
        private readonly string overrideHostname;

        public RequestUrlResolver(string overrideScheme, string overrideHostname)
        {
            this.overrideScheme = overrideScheme;
            this.overrideHostname = overrideHostname;
        }

        public Uri Resolve(HmacRequestInfo msg)
        {
            string ResolveUrlProtocol()
            {
                string p = msg.Headers.FirstOrDefault(Headers.XForwardedProto);
                if (p != null) return p;

                p = msg.Headers.FirstOrDefault(Headers.XForwardedProtocol);
                if (p != null) return p;

                p = msg.Headers.FirstOrDefault(Headers.XUrlScheme);
                if (p != null) return p;

                return !string.IsNullOrWhiteSpace(overrideScheme) ? overrideScheme : msg.Url.Scheme;
            }

            string url = msg.Headers.FirstOrDefault(Headers.XOriginalUrl)
                ?? msg.Headers.FirstOrDefault(Headers.XOriginalUri);

            if (url == null)
                return msg.Url;

            if (Uri.IsWellFormedUriString(url, UriKind.Absolute))
                return new Uri(url);

            string protocol = ResolveUrlProtocol();
            string host = string.IsNullOrWhiteSpace(overrideHostname) ? msg.Url.Host : overrideHostname;

            return new Uri($"{protocol}://{host}{url}");
        }
    }
}