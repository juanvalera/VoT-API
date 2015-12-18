using DotNetOpenAuth.OAuth2;
using System;
using System.Net.Http;
using System.Threading.Tasks;
using System.Threading;
using System.Net.Http.Headers;
using Newtonsoft.Json;
using System.Security.Principal;
using System.Web.Http.Filters;

namespace VoTAPI.Filters
{
    public class ViperAuthFilter : Attribute, IAuthenticationFilter
    {
        public bool AllowMultiple
        {
            get
            {
                return false;
            }
        }

        public Task AuthenticateAsync(HttpAuthenticationContext context, CancellationToken cancellationToken)
        {
            HttpRequestMessage request = context.Request;
            AuthenticationHeaderValue authorization = request.Headers.Authorization;
            // 2. If there are no credentials, do nothing.
            if (authorization == null)
            {
                context.ErrorResult = new AuthenticationFailureResult("Missing credentials", request);
                return Task.FromResult(0);
            }
            // 3. If there are credentials but the filter does not recognize the 
            //    authentication scheme, do nothing.
            if (authorization.Scheme != "Bearer")
            {
                context.ErrorResult = new AuthenticationFailureResult("Missing credentials", request);
                return Task.FromResult(0);
            }

            if (String.IsNullOrEmpty(authorization.Parameter))
            {
                context.ErrorResult = new AuthenticationFailureResult("Missing credentials", request);
                return Task.FromResult(0);
            }
            var authorizationServerUri = new Uri("https://voas.azurewebsites.net/");

            var autorizationServer = new AuthorizationServerDescription()
            {
                AuthorizationEndpoint = new Uri(authorizationServerUri, "OAuth/Authorize"),
                TokenEndpoint = new Uri(authorizationServerUri, "OAuth/Token")
            };

            var webServerClient = new WebServerClient(autorizationServer, "b5da9728-98a4-46b8-80cf-d89bebdc9d33", "03557614-886c-43b0-990d-b5bcd16061a8");

            var clientToken = authorization.Parameter;
            var meClient = new HttpClient(webServerClient.CreateAuthorizingHandler(clientToken));
            try
            {
                var task = meClient.GetStringAsync(new Uri("https://voas.azurewebsites.net/Me/"));
                task.Wait();
                string result = task.Result;
                switch (result)
                {
                    case "2":
                        context.ErrorResult = new BadRequestFilterResult("Invalid Parameters", request);
                        break;
                    case "\"null\"":
                    case "3":
                        context.ErrorResult = new AuthenticationFailureResult("Invalid credentials", request);
                        break;
                    default:
                        dynamic jsonObject = JsonConvert.DeserializeObject(result);
                        GenericIdentity identity = new GenericIdentity(jsonObject.Email.ToString());
                        context.Principal = new GenericPrincipal(identity, new string[] { });
                        break;
                }
            }
            catch (Exception)
            {
                context.ErrorResult = new ServerFilterResult("Internal Error", request);
            }
            return Task.FromResult(0);
        }

        public Task ChallengeAsync(HttpAuthenticationChallengeContext context, CancellationToken cancellationToken)
        {
            return Task.FromResult(0);
            //throw new NotImplementedException();
        }

        /// <summary>
        /// Override
        /// </summary>
        /// <param name="actionContext">Action Context</param>
        //public override void OnActionExecuting(HttpActionContext actionContext)
        //{


        //    base.OnActionExecuting(actionContext);
        //}
    }
}
