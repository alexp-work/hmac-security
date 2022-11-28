using System;
using System.Collections.Generic;
using Xunit;

namespace Security.HMAC
{
    public class RequestUrlResolverFacts
    {
        private readonly RequestUrlResolver resolver;
        public RequestUrlResolverFacts()
        {
            resolver = new RequestUrlResolver(null, null);
        }

        [Fact]
        public void resolve_the_original_uri_after_proxy()
        {
            var msg = new HmacRequestInfo(
                "get",
                new Uri("http://some-proxy-address.com"),
                new Dictionary<string, string>
                {
                    { "X-Forwarded-Proto", "https" },
                    { "X-Original-URI", "/some-path/second-part" }
                });

            var uri = resolver.Resolve(msg);

            Assert.Equal("https://some-proxy-address.com/some-path/second-part", uri.ToString());
        }
    }
}
