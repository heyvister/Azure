#r "Newtonsoft.Json"
#r "System.Web"
#r "System.Threading"
#r "Microsoft.WindowsAzure.Storage"


using System.IO;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.AspNetCore.Http;
using Microsoft.Azure.WebJobs.Host;
using Newtonsoft.Json;
using Microsoft.Extensions.Logging;

using Microsoft.Extensions.Primitives;
using Microsoft.WindowsAzure.Storage.Blob;

using System.Threading.Tasks;
using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Web;
using System.Text;
using System.Threading;

using System.Collections.Generic;

/*
TODO 1: delete old commented code
TODO 2: it should be possible to unite several functions/remove code duplications (i.e. AlteonPostRequest/AlteonGetRequest)
TODO 3: consider separating the AlteonApplyConfig from AlteonPutConfig (and retries separately on put and apply)
TODO 4: errors handling (timeouts, non OK responses, etc.)
TODO 5: through all this code, i don't verify existence of correct post data. in case some are missing, behavior is unexpected
{
    "firstApply": "false",
    "username": "admin",
    "password": "admin",
    "passphrase": "radware",
    "tenantId": "36361a21-c721-4248-9748-8848b2573f18",
    "clientId": "0c46a7db-cf3d-475d-ab18-e0601a94fde5",
    "clientSecret": "OvPYiakHZ9WFRres6dLAtub54Y52LO3WeEqKzrCEVys=",
    "subscriptionId": "6c5564e0-54db-4d63-aa7b-1a7d78dd6f98",
    "resourceGroup": "demoAlteonCluster999",
    "instanceName": "demoAlteonCluster999Vmss_1",
    "accessIp": "168.61.40.73", // used for testing
    "accessPort": "8443",       // used for testing
}
*/

class Globals
{
    // some public global variables
    public static string   _remoteIp = "";
    public static string   _passphrase = "";
    public static string   _lbName = "";
    public static string   _instanceId = "";
    public static dynamic  _requestData = null;
    public static dynamic  _deployParams = null;
    public static ILogger  _log = null;
    public static AuthenticationHeaderValue _authHeader = null;

    public static async Task<bool> Set(HttpRequest req, CloudBlockBlob blob, ILogger log, Microsoft.Azure.WebJobs.ExecutionContext context)
    {
        Blob._blob = blob;
        Globals._log = log;
        string requestBody = "";
        try
        {
            requestBody = await new StreamReader(req.Body).ReadToEndAsync();
            _requestData = JsonConvert.DeserializeObject(requestBody);
            log.LogInformation($"Globals.Set - extracting global data from: {_requestData}");

            _authHeader = Utils.GenerateAuthorizationValue();
            _passphrase = ExtractCallerPassphrase();
            (string name, string id) result =  ExtractInstanceId(); // extract scaleset name and Alteon's instance ID
            _instanceId = result.id;

            // this is for testing only (i.e. when using postman)
            _remoteIp = _requestData?.accessIp; // does not exist when sent from Alteon
            if (string.IsNullOrEmpty(_remoteIp))
            {
                _remoteIp = req.HttpContext.Connection.RemoteIpAddress.ToString();
            }
            log.LogInformation($"Globals.Set - remote ip: {_remoteIp}");

            // some parameters are given in the deployment process and passed to this function by JSON file
            string deployParams = System.IO.File.ReadAllText($@"{context.FunctionDirectory}\function_params.json");
            _deployParams = JsonConvert.DeserializeObject(deployParams);

            _lbName = _deployParams?.Azure.LoadBalancerName;
        }
        catch (Exception ex)
        {
            log.LogError($"Global.Set - an exception occured. request body: {requestBody}\nException: {ex.ToString()}");
        }

        return true;
    }

    static string ExtractCallerPassphrase()
    {
        // extract the passphrase from the request data
        string passphrase = _requestData?.passphrase;
        if (string.IsNullOrEmpty(passphrase))
        {
            return "radware";
        }
        
        return passphrase;
    }

    public static (string name, string id) ExtractInstanceId()
    {
        // extract instance ID from the instance Name (<instance>_<id>)
        string instanceName = _requestData?.instanceName;
        if (string.IsNullOrEmpty(instanceName))
        {
            _log.LogError("request does not contain instance name");
            return ("", "");
        }

        string[] parts = instanceName.Split('_');
        if (parts.Length < 2)
        {
            _log.LogError("request contain instance name but not instance ID");
            return ("", "");
        }

        return (parts[0], parts[1]);
    }
};

class FuncResult
{
    public FuncResult(bool status = false, string message = "", object other = null)
    {
        this.status = status;
        this.message = message;
        this.other = other;
    }

    public bool status {get; set;}
    public string message {get; set;}
    public object other {get; set;}
};

class Configuration
{
    public static async Task<bool> Exists()
    {
        return await Blob.Exists();
    }

    // read configuration file and save it to storage (used after get-config request)
    public static async Task<bool> Save(byte[] responseContent)
    {
        await Blob.PutBuffer(responseContent);
        Globals._log.LogInformation($"Configuration.Save - saved {responseContent.Count()} bytes to configuration blob");

        return true;
    }

    // read configuration from storage and return it as file content
    public static async Task<ByteArrayContent> GetContent()
    {
        byte[] configFileBytes = await Blob.GetBuffer();

        Globals._log.LogInformation($"Configuration.GetContent - total of {configFileBytes.Length} bytes read from storage");
        if (configFileBytes.Length == 0)
        {
            return null;
        }

        ByteArrayContent fileContent = new ByteArrayContent(configFileBytes);
        /*
        fileContent.Headers.ContentDisposition = new ContentDispositionHeaderValue("form-data")
        {
            Name = "Filedata",
            FileName = filename
        };
        fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/gzip");
        */

        return fileContent;
    }
};

class Utils
{
    public static async Task<FuncResult> PostRequest(string url, int numOfTries = 1, string postData = "")
    {
        FuncResult result = new FuncResult();
        //Globals._log.LogError($"Utils.PostRequest - postData: {postData}, tries: {numOfTries}");

        while (numOfTries > 0)
        {
            result = await PostRequest(url, postData);
            if (result.status)
            {
                if ((result.other as HttpResponseMessage).StatusCode == HttpStatusCode.OK)
                {
                    break;
                }
            }
            numOfTries--;
            Globals._log.LogInformation($"Utils.PostRequest - Error during POST [{postData}] to [{url}].\n{numOfTries} more attempts will be done");
            Thread.Sleep(1000); // wait 1 sec before next try
        }

        return result;
    }

    // TODO: consider making this function more generic (i.e. add content)
    static async Task<FuncResult> PostRequest(string url, string postData = "")
    {
        using ( var handler = new HttpClientHandler() )
        {
            // this will actually validate every server certificate
            // this is the only reason for creating the HTTP handler instance
            handler.ServerCertificateCustomValidationCallback = ( message, cert, chain, errors ) => { return true; };

            using (var client = new HttpClient(handler))
            {
                // set request's URL
                client.BaseAddress = new Uri(url);

                // add basic authentication
                client.DefaultRequestHeaders.Authorization = Globals._authHeader;
                if (null == client.DefaultRequestHeaders.Authorization)
                {
                    string message = "Error generating authorization header";
                    Globals._log.LogError($"Utils.PostRequest - {message}");
                    return new FuncResult(false, message);
                }

                // send put-config
                HttpResponseMessage response = await client.PostAsync("", string.IsNullOrEmpty(postData) ? null : new StringContent(postData));
                string responseContent = await response.Content.ReadAsStringAsync();
                if (null == response || response.StatusCode != HttpStatusCode.OK)
                {
                    Globals._log.LogError($"Utils.PostRequest - bad response content: {responseContent}");

                    string message = $"Received request error from {response.RequestMessage.RequestUri}";
                    Globals._log.LogError($"Utils.PostRequest - {message}");
                    return new FuncResult(false, message);
                }

                Globals._log.LogInformation($"Utils.PostRequest - response for [{url}, {postData}]: {responseContent}");

                return new FuncResult(true, responseContent, response);
            }
        }
    }

    // just use POST request for the given URL and content
    public static async Task<HttpResponseMessage> PostUrl(string url, StringContent content)
    {
        using (var handler = new HttpClientHandler())
        {
            // this will actually validate every server certificate
            // this is the only reason for creating the HTTP handler instance
            handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => { return true; };

            using (var client = new HttpClient(handler))
            {
                client.BaseAddress = new Uri(url);

                return await client.PostAsync(url, content);
            }
        }
    }

    // extract the username and password from the request's data and genetate an authentication header value
    public static System.Net.Http.Headers.AuthenticationHeaderValue GenerateAuthorizationValue()
    {
        // extract the username and password from the request's body
        string username = Globals._requestData?.username;
        string password = Globals._requestData?.password;

        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
        {
            return null;
        }

        var byteArray = Encoding.ASCII.GetBytes($"{username}:{password}");
        return new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", Convert.ToBase64String(byteArray));
    }

    // extract ip and port either from the request (remote ip/post data) or by default (port)
    public static string GetCallerAddress(HttpRequest req, Dictionary<string, string> idPortTable)
    {
        // for debugging - i can pass the port number in the request's data
        string remotePort = Globals._requestData?.accessPort;
        if (string.IsNullOrEmpty(remotePort))
        {
            // default port when using single IP setup
            remotePort = "8443";

            // search for the appropriate port in the given table
            foreach (var kvp in idPortTable)
            {
                // skip initiating Alteon
                if (string.Equals(Globals._instanceId, kvp.Key, StringComparison.OrdinalIgnoreCase))
                {
                    // generate IP from request data and port from the above dictionary
                    remotePort = kvp.Value;

                    break;
                }
            }
        }

        string ipAddress = $"{Globals._remoteIp}:{remotePort}";

        return ipAddress;
    }

    public static Dictionary<string, string> BuildPortsTable(dynamic natRules)
    {
        Dictionary<string, string> ports = new Dictionary<string, string>();

        // NAT rules response data may look like this:
        /*
        {
            "value": [
                {
                    "name": "natRule1.1",
                    "id": "/subscriptions/subid/resourceGroups/testrg/providers/Microsoft.Network/loadBalancers/lb1/inboundNatRules/natRule1.1",
                    "properties": {
                        "provisioningState": "Succeeded",
                        "frontendIPConfiguration": {
                            "id": "/subscriptions/subid/resourceGroups/testrg/providers/Microsoft.Network/loadBalancers/lb1/frontendIPConfigurations/ip1"
                        },
                        "frontendPort": 3390,
                        "backendPort": 3389,
                        "enableFloatingIP": false,
                        "idleTimeoutInMinutes": 4,
                        "protocol": "Tcp",
                        "enableTcpReset": true,
                        "backendIPConfiguration": {
                            "id": "/subscriptions/subid/resourceGroups/testrg/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1/virtualMachines/1/networkInterfaces/nic1/ipConfigurations/ip1"
                        }
                    }
                },
                {
                    "name": "natRule1.3",
                    "id": "/subscriptions/subid/resourceGroups/testrg/providers/Microsoft.Network/loadBalancers/lb1/inboundNatRules/natRule1.3",
                    "properties": {
                        "provisioningState": "Succeeded",
                        "frontendIPConfiguration": {
                            "id": "/subscriptions/subid/resourceGroups/testrg/providers/Microsoft.Network/loadBalancers/lb1/frontendIPConfigurations/ip1"
                        },
                        "frontendPort": 3392,
                        "backendPort": 3389,
                        "enableFloatingIP": false,
                        "idleTimeoutInMinutes": 4,
                        "protocol": "Tcp",
                        "enableTcpReset": true,
                        "backendIPConfiguration": {
                            "id": "/subscriptions/subid/resourceGroups/testrg/providers/Microsoft.Compute/virtualMachineScaleSets/vmss1/virtualMachines/3/networkInterfaces/nic1/ipConfigurations/ip1"
                        }
                    }
                }
            ]
        }
        */            
        // go through all the rules and:
        // 1. get the instance rule name (value[i].name)
        // 2. extract it's id (instance rule name == <rule name>.<id>)
        // 3. get the frontend port (values[i].properties.frontendPort)
        // 4. add id & port to dictionary

        foreach (var value in natRules.value)
        {
            string rulename = value.name;
            string[] parts = rulename.Split('.');

            if (parts.Length < 2)
            {
                Globals._log.LogError($"NAT rules response does not contain instance ID: {rulename}");
                continue;
            }

            string port = value.properties.frontendPort;
            ports.Add(parts[1], port);
        }

        Globals._log.LogInformation($"Utils.BuildPortsTable - [instance id, port number]: {string.Join(", ", ports)}");
        return ports;
    }

};

class Blob
{
    public static CloudBlockBlob _blob;

    public static async Task<bool> Exists()
    {
        if (null != _blob)
        {
            try
            {
                return await _blob.ExistsAsync();
            }
            catch (Exception ex)
            {
                Globals._log.LogError($"Blob.Exists - an exception occured. blob: {_blob.Name}\nException: {ex.ToString()}");
            }
        }

        return false;
    }

    public static async Task<bool> PutBuffer(byte[] buffer)
    {
        if (null != _blob)
        {
            try
            {
                await _blob.UploadFromByteArrayAsync(buffer, 0, buffer.Length);
                Globals._log.LogInformation($"Blob.PutBuffer - wrote {buffer.Length} bytes to {_blob.Name}");

                return true;
            }
            catch (Exception ex)
            {
                Globals._log.LogError($"Blob.PutBuffer - an exception occured. blob: {_blob.Name}\nException: {ex.ToString()}");
            }
        }

        return false;
    }

    public static async Task<byte[]> GetBuffer()
    {
        if (null != _blob)
        {
            try
            {
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    //Download the blob.
                    await _blob.DownloadToStreamAsync(memoryStream);

                    byte[] buffer = memoryStream.ToArray();
                    Globals._log.LogInformation($"Blob.GetBytes - read {buffer.Length} bytes");

                    return buffer;
                }
            }
            catch (Exception ex)
            {
                Globals._log.LogError($"Blob.GetBuffer - an exception occured. blob: {_blob.Name}\nException: {ex.ToString()}");
            }
        }

        return null;
    }
};

class ClusterSync
{
    // upon 'apply' command, get the updated configuration from the calling Alteon, save it and update all other
    // Alteons in the cluster
    public static async Task<FuncResult> HandleApplyRequest(HttpRequest req)
    {
        Globals._log.LogInformation($"ClusterSync.HandleApplyRequest - first collect NAT rules");
        // get a list of all NAT rules
        dynamic natRules = await AzureInterface.GetInboundNatRules();
        // make a list of instance-ID to port according to nat rules response
        Dictionary<string, string> idPortTable = Utils.BuildPortsTable(natRules);

        // get the configuration from the calling Alteon
        Globals._log.LogInformation($"ClusterSync.HandleApplyRequest - get configuration from caller");
        HttpResponseMessage response = await AlteonInterface.GetConfig(req, idPortTable, 3);
        if (null == response || response.StatusCode != HttpStatusCode.OK)
        {
            string responseStatus = await response.Content.ReadAsStringAsync();
            Globals._log.LogInformation($"ClusterSync.HandleApplyRequest - response status: {responseStatus}");
            
            string message = $"Error {responseStatus} when trying to get Alteon's configuration (from {response.RequestMessage.RequestUri})";
            Globals._log.LogError($"ClusterSync.HandleApplyRequest - {message}");
            return new FuncResult(false, message);
        }

        // read the response data
        byte[] responseContent = await response.Content.ReadAsByteArrayAsync();
        // save the configuration received
        await Configuration.Save(responseContent);

        // now start the sync process...

        // now update all other Alteons...
        // TODO: without await i can send all updates together, but (currently) without knowing when it completes
        FuncResult result = await AlteonInterface.UpdateOthers(idPortTable, Globals._instanceId);

        return result;
    }


    // updated the calling Alteon with an updated configuration (if exist)
    public static async Task<FuncResult> HandleFirstApplyRequest(HttpRequest req)
    {
        FuncResult result;

        Globals._log.LogInformation("ClusterSync.HandleFirstApplyRequest - calling Azure.GetInboundNatRules");

        // get a list of all NAT rules
        dynamic natRules = await AzureInterface.GetInboundNatRules();
        if (null == natRules)
        {
            string message = "failed to retrieve NAT rules";
            Globals._log.LogError($"HandlleFirstApplyRequest - {message}");
            return new FuncResult(false, message);
        }

        // make a list of instance-ID to port according to nat rules response
        Dictionary<string, string> idPortTable = Utils.BuildPortsTable(natRules);
        Globals._log.LogInformation($"ClusterSync.HandleFirstApplyRequest - id-port table:\n{idPortTable}");

        // get the host name/ip from the request
        string address = Utils.GetCallerAddress(req, idPortTable);
        if (string.IsNullOrEmpty(address))
        {
            string message = $"caller address not found in NAT rules ([instance id, port number]): {string.Join(", ", idPortTable)}";
            Globals._log.LogError($"ClusterSync.HandleFirstApplyRequest - {message}");
            return new FuncResult(false, message);
        }

        // if storage is not empty - need to update calling Alteon's configuration
        Globals._log.LogInformation("ClusterSync.HandleFirstApplyRequest - check configuration files existance");
        if (await Configuration.Exists())
        {
            // use updated configuration to send it back to the requesting Alteon
            result = await AlteonInterface.PutConfig(address, 3);
        }
        else
        {
            Globals._log.LogInformation("ClusterSync.HandleFirstApplyRequest - configuration not updated yet");

            // add SSL certificate
            // only on first apply, when configuration was not uploaded yet
            result = await AlteonCertificate.Set(address);
            
        }

        if (!result.status)
        {
            return result;
        }

        // now add license
        result = await AlteonGelLicense.Set(address);

        return result;
    }
};

/// a collection of functionalities that handle GEL license
class AlteonGelLicense
{
    // license related
    static string _licEntitlementIdKey = "lmLicOperPendingEntitlementId";
    static string _licThroughputKey = "lmLicOperThroughput";
    static string _licSubscriberKey = "lmLicOperSubscrAddOn";
    static string _licSyncKey = "lmLicOperSynclic";
    static string _licSyncValue = "0"; // [0(start)]

    /// set license to Alteon (the one sending the first-apply)
    public static async Task<FuncResult> Set(string address)
    {
        string licEntitlementIdValue = Globals._deployParams?.GelLicense.EntitlementId;
        string licThroughputValue = Globals._deployParams?.GelLicense.Throughput;
        string licSubscriberValue = Globals._deployParams?.GelLicense.Subscriber;
		string postData = "";

        Globals._log.LogInformation($"AlteonGelLicense.Set - entry");

        // to add a license, we should:
        // 1. submit the entitlement id
        // 2. submit the throughput
        // 3. submit subscriber (perform/secure/ignore)
        // 4. commit (sync) license

        string url = $"https://{address}/config";

        // submit entitlement id
        //string postData = $"{{\"{_licEntitlementIdKey}\": \"{licEntitlementIdValue}\"}}";
        FuncResult result = await Utils.PostRequest(url, 3, postData);
        if (!result.status)
        {
            return result;
        }

        // submit throughput
       // postData = $"{{\"{_licThroughputKey}\": \"{licThroughputValue}\"}}";
        result = await Utils.PostRequest(url, 3, postData);
        if (!result.status)
        {
            return result;
        }

        // submit subscriber
        //postData = $"{{\"{_licSubscriberKey}\": \"{licSubscriberValue}\"}}"; // 0/2/3 (ignore/perform/secure)
        result = await Utils.PostRequest(url, 3, postData);
        if (!result.status)
        {
            return result;
        }

        // now sync
       // postData = $"{{\"{_licSyncKey}\": \"{_licSyncValue}\"}}"; // 0 (start)
        result = await Utils.PostRequest(url, 3, postData);

        return result;
    }
};

// a collection of functions to handle SSL certificate injection
class AlteonCertificate
{
    /// set license to Alteon (the one sending the first-apply)
    public static async Task<FuncResult> Set(string address)
    {
        // 1. set certificate key
        // 2. set certificate data

        // read key and data from parameters file
        string id = Globals._deployParams?.Certificate.Id;
        string passphrase = Globals._deployParams?.Certificate.Passphrase;
        //string key = System.IO.File.ReadAllText($@"{Globals._localPath}\cert_key.txt");
        string key = Globals._deployParams?.Key;
        //string data = System.IO.File.ReadAllText($@"{Globals._localPath}\cert_data.txt");
        string data = Globals._deployParams?.Data;

        Globals._log.LogInformation($"AlteonCertificate.Set - key size: {key.Length}, data size: {data.Length}");

        // inject key
        string url = $"https://{address}/config/sslcertimport?renew=0&renewK=0&id={id}&type=key&src=txt&passphrase={passphrase}";
        FuncResult result = await Utils.PostRequest(url, 3, key);
        if (!result.status)
        {
            return result;
        }

        url = $"https://{address}/config/sslcertimport?renew=0&renewK=0&id={id}&type=cert&src=txt";
        result = await Utils.PostRequest(url, 3, data);
        if (!result.status)
        {
            return result;
        }

        result = await AlteonInterface.ApplyConfig(address);

        return result;
    }
};

// a collection of functions to interact with Azure
class AzureInterface
{
    // build the REST API to get a list of NAT rules for a specific Scale Set
    static string GenerateNatRulesListUrl()
    {
        string subscriptionId = Globals._requestData?.subscriptionId;
        string resourceGroup = Globals._requestData?.resourceGroupName;
        string apiVersion = "2018-08-01";

        return $"https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroup}/providers/Microsoft.Network/loadBalancers/{Globals._lbName}/inboundNatRules?api-version={apiVersion}";
    }

    // each NAT rule also reflects a VM in the cluster, so i'm actually getting the cluster VMs as well
    public static async Task<dynamic> GetInboundNatRules()
    {
        Globals._log.LogInformation("Azure.GetInboundNatRules - entry");
        // generate the appropriate URL
        string queryUrl = GenerateNatRulesListUrl();

        // send GET request to ARM to retrieve NAT rules
        HttpResponseMessage response = await GetHttpResponse(queryUrl);

        string responseContent = await response.Content.ReadAsStringAsync();
        //Globals._log.LogInformation($"Azure.GetInboundNatRules - response: {responseContent}");

        return JsonConvert.DeserializeObject(responseContent);
    }

    // send get request to ARM and return the response message
    static async Task<HttpResponseMessage> GetHttpResponse(string url)
    {
        Globals._log.LogInformation($"Azure.GetHttpResponse - request url: {url}");
        // first get an authorization token
        // TODO: handle a global token with expiration mechanism
        string token = await GetToken();

        using (var handler = new HttpClientHandler())
        {
            // this will actually validate every server certificate
            // this is the only reason for creating the HTTP handler instance
            handler.ServerCertificateCustomValidationCallback = (message, cert, chain, errors) => { return true; };

            using (var client = new HttpClient(handler))
            {
                client.BaseAddress = new Uri(url);
                client.DefaultRequestHeaders.Add("Authorization", $"Bearer {token}");

                HttpResponseMessage response = await client.GetAsync("");
                Globals._log.LogInformation($"Azure.GetHttpResponse - response: {response.ToString()}");

                return response;
            }
        }
    }

    // get an authorization token from ARM
    static async Task<string> GetToken()
    {
        // ask for token using the given credentials
        string tenantId = Globals._requestData?.tenantId;
        string clientId = Globals._requestData?.clientId;
        string clientSecret = Globals._requestData?.clientSecret;

        // request a token
        string url = $"https://login.windows.net/{tenantId}/oauth2/token";

        string resourceData = $"https://management.core.windows.net/&client_id={clientId}&grant_type=client_credentials&client_secret={clientSecret}";
        StringContent content = new StringContent($"resource={resourceData}", Encoding.UTF8, "application/x-www-form-urlencoded");

        HttpResponseMessage response = await Utils.PostUrl(url, content);

        string responseContent = await response.Content.ReadAsStringAsync();

        // extract the token from the response
        dynamic resData = JsonConvert.DeserializeObject(responseContent);
        string token = resData?.access_token;
        Globals._log.LogInformation($"Azure.GetToken - response: {token}");

        return token;
    }
};

// a collection of functions to interact with Alteon
class AlteonInterface
{
    public static async Task<HttpResponseMessage> GetConfig(HttpRequest req, Dictionary<string, string> idPortTable, int numOfTries)
    {
        HttpResponseMessage response = null;

        // get the host name/ip from the request
        string ipAddress = Utils.GetCallerAddress(req, idPortTable);
        string url = $"https://{ipAddress}/config/getcfg?pkey=yes";
        Globals._log.LogInformation($"Alteon.GetConfig - going to query {url}");

        while (numOfTries > 0)
        {
            response = await GetConfig(url);
            if (response.StatusCode == HttpStatusCode.OK)
            {
                break;
            }
            numOfTries--;
            Globals._log.LogInformation($"Alteon.GetConfig - Error during Get-Config, {numOfTries} more attempts will be done");
            Thread.Sleep(1000); // wait 1 sec before next try
        }

        return response;
    }

    // generic get-config method - send get-config request to Alteon VM
    public static async Task<HttpResponseMessage> GetConfig(string url)
    {
        using ( var handler = new HttpClientHandler() )
        {
            // this will actually validate every server certificate
            // this is the only reason for creating the HTTP handler instance
            handler.ServerCertificateCustomValidationCallback = ( message, cert, chain, errors ) => { return true; };

            using (var client = new HttpClient(handler))
            {
                // add basic authentication
                client.DefaultRequestHeaders.Authorization = Globals._authHeader;
                if (null == client.DefaultRequestHeaders.Authorization)
                {
                    string message = "Alteon.GetConfig - Error generating authorization header";
                    Globals._log.LogError(message);
                    return null;
                }

                client.DefaultRequestHeaders.Add("Passphrase", Globals._passphrase);

                client.BaseAddress = new Uri(url);
                HttpResponseMessage response = await client.GetAsync("");

                Globals._log.LogInformation($"Alteon.GetConfig - response: {response}");

                return response;
            }
        }
    }

    public static async Task<FuncResult> PutConfig(string address, int numOfTries)
    {
        FuncResult result = new FuncResult(false, "");

        while (numOfTries > 0)
        {
            result = await PutConfig(address);
            if (result.status)
            {
                break;
            }
            numOfTries--;
            Globals._log.LogInformation($"Alteon.PutConfig - Error during Put-Config, {numOfTries} more attempts will be done");
            Thread.Sleep(1000); // wait 1 sec before next try
        }

        return result;
    }

    // generic put-config method - use given configuration file and send it to an Alteon VM
    static async Task<FuncResult> PutConfig(string address)
    {
        string url = $"https://{address}/config/configimport?pkey=yes";
        Globals._log.LogInformation($"Alteon.PutConfig - going to put config to {url}");

        using ( var handler = new HttpClientHandler() )
        {
            // this will actually validate every server certificate
            // this is the only reason for creating the HTTP handler instance
            handler.ServerCertificateCustomValidationCallback = ( message, cert, chain, errors ) => { return true; };

            using (var client = new HttpClient(handler))
            {
                // set request's URL
                client.BaseAddress = new Uri(url);

                // add basic authentication
                client.DefaultRequestHeaders.Authorization = Globals._authHeader;
                if (null == client.DefaultRequestHeaders.Authorization)
                {
                    string message = "Error generating authorization header";
                    Globals._log.LogError($"Alteon.PutConfig - {message}");
                    return new FuncResult(false, message);
                }

                Globals._log.LogInformation($"Alteon.PutConfig - authorization added: {client.DefaultRequestHeaders.Authorization.ToString()}");

                client.DefaultRequestHeaders.Add("Passphrase", Globals._passphrase);

                using (var content = new MultipartFormDataContent())
                {
                    /*
                    it makes sense to use a one-time-created value to add to the request's content, as this
                    value would be created once outside this function and be reused in consequtive calls.
                    apprently, after each request, this value is disposed, so i need to create it every
                    time when creating a new request :-(
                    */
                    ByteArrayContent configFile = await Configuration.GetContent();
                    if (null == configFile)
                    {
                        return new FuncResult(false, "Alteon.PutConfig - couldn't get a valid configuration");
                    }
                    content.Add(configFile);

                    // send put-config
                    HttpResponseMessage response = await client.PostAsync("", content);
                    Globals._log.LogInformation($"Alteon.PutConfig - response: {response.ToString()}");
                    string responseContent = await response.Content.ReadAsStringAsync();
                    Globals._log.LogInformation($"Alteon.PutConfig - response content: {responseContent}");

                    if (response.StatusCode != HttpStatusCode.OK)
                    {
                        string message = $"Error {responseContent} when trying to put-config to {url}";
                        Globals._log.LogError($"Alteon.PutConfig - {message}");
                        return new FuncResult(false, message);
                    }

                    // now send apply to that Alteon
                    FuncResult result = await ApplyConfig(address);
                    Globals._log.LogInformation($"Alteon.PutConfig - result of apply: {result}");

                    return new FuncResult(true, responseContent);
                }
            }
        }
    }

    // go through all existing Alteons and sent put-config request to them (skip the originating Alteon)
    public static async Task<FuncResult> UpdateOthers(Dictionary<string, string> instancesPorts, string instanceId)
    {
        FuncResult result = new FuncResult();
        int successfulApplys = 0;
        int totalApplys = 0;

        Globals._log.LogInformation("Alteon.UpdateOthers - enter");

        foreach (KeyValuePair<string, string> kvp in instancesPorts)
        {
            // skip initiating Alteon
            if (string.Equals(instanceId, kvp.Key, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }
            // generate IP from request data and port from the above dictionary
            string address = $"{Globals._remoteIp}:{kvp.Value}";
            Globals._log.LogInformation($"Alteon.UpdateOthers - handling address {address}");

            result = await PutConfig(address, 3);
            if (result.status)
            {
                successfulApplys += 1;
            }
            totalApplys += 1;
        }

        result.status = true;
        result.message = $"successfully applied {successfulApplys} VMs out of {totalApplys} tries";
        return result;
    }

    public static async Task<FuncResult> ApplyConfig(string address)
    {
        Globals._log.LogInformation("Alteon.ApplyConfig - entry");
        
        string url = $"https://{address}/config?action=clusterSyncApply";

        return await Utils.PostRequest(url);
    }
};

public static async Task<IActionResult> Run(HttpRequest req, CloudBlockBlob blob, ILogger log, Microsoft.Azure.WebJobs.ExecutionContext context)
{
    string reqMethod = req.Method;
    log.LogInformation($"C# HTTP trigger function processing a {reqMethod} request.");
    if (!string.Equals(reqMethod, "post", StringComparison.OrdinalIgnoreCase))
    {
        return new BadRequestObjectResult("Please use a POST request when using this function");
    }

    // simple logic:
    // 1. if first apply and storage contains a configuration -
    //    - put configuration from storage to Alteon
    // 2. if apply -
    //    - get configuration from Alteon
    //    - save configuration to storage
    //    - populate configuration too all other Alteons in the set
    // x. if first apply and configuration storage is empty (we don't really need this) -
    //    - get configuration from Alteon
    //    - store the configuration in cloud storage
    //    - populate configuration to all other Alteons in the set

    // set some globals
    bool res = await Globals.Set(req, blob, log, context);
    if (res)
    {
        // extract first apply indication from request body
        string firstApply = Globals._requestData?.firstApply;

        // indication must exist
        if (!string.IsNullOrEmpty(firstApply))
        {
            // check for first apply indication
            if (string.Equals(firstApply, "true", StringComparison.OrdinalIgnoreCase))
            {
                var result = await ClusterSync.HandleFirstApplyRequest(req);
                Globals._log.LogInformation($"ClusterSync.HandleFirstApplyRequest returned {result.ToString()}");

                return (ActionResult)new OkObjectResult($"ClusterSync.HandleFirstApplyRequest result: {result.ToString()}");
            }
            // check for apply indication (first apply is false)
            else if (string.Equals(firstApply, "false", StringComparison.OrdinalIgnoreCase))
            {
                var result = await ClusterSync.HandleApplyRequest(req);
                Globals._log.LogInformation($"HandleApplyRequest returned {result.ToString()}");

                return (ActionResult)new OkObjectResult($"apply, put-config result: {result.ToString()}");
            }
            else
            {
                return new BadRequestObjectResult("Please pass a valid value (true/false) for 'firstApply' indication in the request body");
            }
        }
        else
        {
            return new BadRequestObjectResult("Please pass a 'firstApply' indication on the query string or in the request body");
        }
    }

    return new BadRequestObjectResult("Failed extracting required values from request's data");
}

