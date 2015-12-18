using VoTAPI.Models;
using DataCollector.RestClient;
using DataCollector.RestClient.Models;
using DataCollector.ViperRepo;
using System;
using System.Configuration;
using System.Linq;
using System.Net;
using System.Web.Http;
using VoTAPI.Filters;

namespace VoTAPI.Controllers
{

    public class OAuthIntegrationController : ApiController
    {

        [HttpPost]
        [Route("api/oauthintegration/fitbit")]
        public IHttpActionResult Post([FromBody]FitbitCodeRequest model)
        {
            string FitbitName = "Fitbit";
            try
            {
                ViperRepo repo = new ViperRepo();
                string serialNumber = FitbitName + model.Email.Replace("@", "").Replace(".", "");

                string headerValue = Request.Headers.GetValues("Authorization").FirstOrDefault();
                if (!string.IsNullOrWhiteSpace(headerValue))
                {
                    bool hasError = false;


                    FitbitClient fitbit = new FitbitClient();
                    fitbit.ClientId = ConfigurationManager.AppSettings["FitbitClientId"];
                    fitbit.SecretKey = ConfigurationManager.AppSettings["FitbitSecretKey"];

                    AccessTokenAuthorizationCode token = fitbit.GetAccessTokenAuthorizationCode(model.Code);
                    OAuthIntegrationEntities context = new OAuthIntegrationEntities();

                    ThirdPartyUserIdentity identity = context.ThirdPartyUserIdentity.FirstOrDefault(th => th.UserId == model.Email.Trim());
                    if (identity == null)
                    {
                        do
                        {
                            try
                            {
                                ViperResponse result = repo.RegisterDevice(serialNumber, FitbitName, FitbitName, headerValue);
                                hasError = false;
                                switch (result)
                                {
                                    case ViperResponse.Code2:
                                        return this.StatusCode(HttpStatusCode.Conflict);
                                    case ViperResponse.Code3:
                                        return Unauthorized();
                                }
                            }
                            catch (Exception ex)
                            {
                                hasError = true;
                            }
                        } while (hasError);

                        identity = new ThirdPartyUserIdentity();
                        identity.ServiceId = 1;
                        identity.Token = token.AccessToken;
                        identity.RefreshToken = token.RefreshToken;
                        identity.UserId = model.Email.Trim();
                        identity.TokenExpirationDate = DateTime.Now.AddHours(1);
                        identity.CreateDate = DateTime.Now;
                        context.ThirdPartyUserIdentity.Add(identity);
                        context.SaveChanges();
                        return Ok();

                    }
                    else
                    {
                        identity.ServiceId = 1;
                        identity.Token = token.AccessToken;
                        identity.RefreshToken = token.RefreshToken;
                        identity.UserId = model.Email.Trim();
                        identity.TokenExpirationDate = DateTime.Now.AddHours(1);
                        context.SaveChanges();
                        return Ok();
                    }
                }

                return Unauthorized();

            }
            catch (Exception ex)
            {
                return InternalServerError();
            }

        }

        [ViperAuthFilter]
        [Route("api/affiliations")]
        public IHttpActionResult Get()
        {
            OAuthIntegrationEntities context = new OAuthIntegrationEntities();
            try
            {
                var services = context.ThirdPartyUserIdentity
                    .Where(ui => ui.UserId == this.User.Identity.Name)
                    .Select(ui => new { ServiceId = ui.ThirdPartyServices.Id, ServiceName = ui.ThirdPartyServices.ServiceName });
                return Ok(services);
            }
            catch (Exception)
            {
                return InternalServerError();
            }
        }
    }
}
