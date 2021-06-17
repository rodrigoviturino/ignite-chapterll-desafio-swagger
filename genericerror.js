// Error handling - conditions evaluation and variable setup
// Author: Rafael Pancher @ Claro Brasil
// Date: 2019-12-08

var result_http_code;
var detailed_msg = "";
var isJson;
var json;
var xml;

var curr_result_http_code;
var curr_error_code;
var curr_message;
var curr_detailed_msg;

const backendStr = "Backend: ";

//var bodyAlreadyParsed;

try
{
    var fault_name = context.getVariable("fault.name");
    var customfault_name = context.getVariable("customfault.name");
    var message_status_code = context.getVariable("message.status.code");
    var initial_verb = context.getVariable("initial.verb");
    //var fault_policy = context.getVariable("fault.policy");
    //var xmlattack_failed = context.getVariable("xmlattack.failed");

    var checkingPayloadForCompatibility = false;
    var attemptingPayloadParse = false;
    var returningBlankBody = false;
    var returningPayloadAsIs = false;
    var settingQuotaLimitHeaders = false;


    // Error code from current faults
    /*
    if (context.getVariable("xmlattack.failed"))
    {
        result_http_code = 400;
        detailed_msg = "Threatening content check failed.";
        //context.setVariable('fault.name', customfault_name);
    }
    else if (context.getVariable("ratelimit.SA-LimitExecution.failed"))
    {
        result_http_code = 429;
        detailed_msg = "Spike protection triggered1.";
        //context.setVariable('fault.name', customfault_name);
    }
    else */
    if (customfault_name)
    {
        switch (customfault_name)
        {
            case "ClientAuthenticationCheck":
                result_http_code = 401;
                detailed_msg = "Client authentication failed.";
                break;
            case "BadClientAuthHeader":
                result_http_code = 401;
                detailed_msg = "Client authentication missing or ambiguous.";
                break;
            case "BadClientAuthMethod":
                result_http_code = 403; //
                detailed_msg = "Client authentication method not allowed for the application.";
                break;
            case "BasicClientBadSecret":
                result_http_code = 401;
                detailed_msg = "Client authentication failed.";
                break;
            case "InvalidAppType":
                result_http_code = 401;
                detailed_msg = "Client type unknown.";
                break;
            case "ProdRequiredAppType":
                result_http_code = 401;
                detailed_msg = "Client type not allowed for the product.";
                break;
            case "ProductRequiredAuthType":
                result_http_code = 401;
                detailed_msg = "Authentication type for product unknown.";
                break;
            case "ClientAuthRequired":
                result_http_code = 500;
                detailed_msg = "Client authentication data required.";
                break;
            case "InvalidAuthTypeAttribute":
                result_http_code = 500;
                detailed_msg = "Client configuration missing.";
                break;
            case "UserAuthenticationCheck":
                result_http_code = 401;
                detailed_msg = "User authentication failed.";
                break;
            case "InvalidUserAuthHeader":
                result_http_code = 401;
                detailed_msg = "User authentication invalid.";
                break;
            case "UserInfoCalloutFailed":
                result_http_code = 401;
                detailed_msg = "User token introspection failed.";
                break;
            case "UserInfoCalloutInvalidToken":
                result_http_code = 401;
                detailed_msg = "User token invalid or expired.";
                break;
            case "PublicClientCheck":
                result_http_code = 401;
                detailed_msg = "Public client check failed.";
                break;
            case "MissingClientCredentials":
                result_http_code = 401;
                detailed_msg = "Missing credentials.";
                break;
            case "JWTCheck":
                result_http_code = 401;
                detailed_msg = "JWT check failed.";
                break;
            case "UserJWTDecodeFailed":
                result_http_code = 401;
                detailed_msg = "JWT check failed.";
                break;
            case "ClientConflictCheck":
                result_http_code = 400;
                detailed_msg = "Client credential conflict.";
                break;
            case "IPWhitelistCheck":
                result_http_code = 403;
                detailed_msg = "IP whitelist check failed.";
                break;
            case "IPWhitelistAppConfig":
                result_http_code = 403;
                detailed_msg = "IP whitelist must exist for the client.";
                break;
            case "UserAuthorizationCheck":
                result_http_code = 403;
                detailed_msg = "User authorization check failed.";
                break;
            case "UserAuthorizationHeaderCheck":
                result_http_code = 403;
                detailed_msg = "User authorization header missing.";
                break;
            case "UserAuthorizationCallout": // MobileAuthorization
                result_http_code = 403;
                detailed_msg = "User authorization server failed.";
                break;
            case "SpikeArrestCheck":
                result_http_code = 429;
                detailed_msg = "Spike protection triggered.";
                break;
            case "QuotaCheck":
                result_http_code = 429;
                detailed_msg = "Quota check failed.";
                settingQuotaLimitHeaders = true;
                break;
            case "CaptchaCheck":
                result_http_code = 403;
                detailed_msg = "Captcha check failed.";
                break;
            case "PayloadSizeLowerLimitCheck":
                result_http_code = 400;
                detailed_msg = "Payload limits check failed.";
                break;
            case "PayloadSizeUpperLimitCheck":
                result_http_code = 413;
                detailed_msg = "Payload limits check failed.";
                break;
            case "URISizeUpperLimitCheck":
                result_http_code = 414;
                detailed_msg = "URI limits check failed.";
                break;
            case "ThreateningContentValidation":
                result_http_code = 400;
                detailed_msg = "Threatening content check failed.";
                break;
            case "ParameterValidation":
                result_http_code = 400;
                detailed_msg = "Parameter validation failed.";
                break;
            case "URIParameterValidation":
                result_http_code = 400;
                detailed_msg = "URI parameter validation failed.";
                break;
            case "PathNotFoundError":
                result_http_code = 404;
                detailed_msg = "Path not found.";
                break;
            case "MethodNotAllowedError":
                result_http_code = 405;
                detailed_msg = "Method not allowed.";
                break;
            case "RequestTransform":
                result_http_code = 400;
                detailed_msg = "Request transformation failed.";
                break;
            case "ResponseTransform":
                result_http_code = 500;
                detailed_msg = "Response transformation failed.";
                break;
            case "BusinessFault":
                result_http_code = 422;
                detailed_msg = "Business fault occurred.";
                break;
            case "CORSPreflightBadOrigin":
                result_http_code = 403;
                returningBlankBody = true;
                break;
            case "BlankResponse":
                returningBlankBody = true;
                break;
            case "NonStandardFaultResponse":
                returningPayloadAsIs = true;
                break;
            case "DataRedaction":
                result_http_code = 500;
                detailed_msg = "Response data redaction failed.";
                break;
            case "DataRedactionContentType":
                result_http_code = 500;
                detailed_msg = "Response data redaction failed. Unsupported content type.";
                break;
            case "DataRedactionPayload":
                result_http_code = 500;
                detailed_msg = "Response data redaction failed. Unsupported payload content.";
                break;
        }
        context.setVariable('fault.name', customfault_name);
    }
    else if (fault_name)
    {
        switch (fault_name)
        {
            case "InvalidBasicAuthenticationSource":
                result_http_code = 401;
                detailed_msg = "Client authentication failed.";
                break;

            case "InvalidApiKeyForGivenResource":
                result_http_code = 403;
                detailed_msg = "Client authorization failed.";
                break;

            case "RaiseFault":
                // if (message_status_code >= 400 && message_status_code < 600)
                //     result_http_code = message_status_code;
                // else
                //     result_http_code = 500;

                // handle body
                checkingPayloadForCompatibility = true;
                break;

            case "ErrorResponseCode":
                // if (message_status_code >= 400 && message_status_code < 600)
                //     result_http_code = message_status_code;
                // else
                //     result_http_code = 500;

                detailed_msg = "Backend error.";

                // handle body
                checkingPayloadForCompatibility = true;
                attemptingPayloadParse = true;
                break;

            case "NoActiveTargets":
                result_http_code = 503;
                break;

            case "ExceededContainerDepth":
            case "ExceededObjectEntryCount":
            case "ExceededArrayElementCount":
            case "ExceededObjectEntryNameLength":
            case "ExceededStringValueLength":
            case "SourceUnavailable":
            case "NonMessageVariable":
            case "ThreatDetected":
                result_http_code = 400;
                break;

            case "invalid_access_token":
            case "access_token_expired":
            case "consumer_key_expired":
                detailed_msg = "Client authentication token invalid.";
            case "FailedToResolveAccessToken":
            case "FailedToResolveToken":
            case "FailedToResolveAuthorizationCode":
            case "InvalidOperation":
                result_http_code = 401;
                break;

            case "IPDeniedAccess":
                detailed_msg = "Global IP whitelist check failed.";
            case "InsufficientScope":
                result_http_code = 403;
                break;

            case "OperationNotFound":
                result_http_code = 404;
                break;

            case "SpikeArrestViolation":
            case "InvalidMessageWeight":
            case "ErrorLoadingProperties":
            case "InvalidAllowedRate":
            case "FailedToResolveSpikeArrestRate":
                result_http_code = 429;
                break;

            case "ExecutionFailed":
            case "ScriptExecutionFailed":
                result_http_code = 500;
                break;

            case "SharedFlowNotFound":
                result_http_code = 500;
                detailed_msg = "Deployment problem.";
                break;

            case "UnresolvedVariable":
            case "FCVariableResolutionFailed":
                result_http_code = 500;
                detailed_msg = "Unresolved variable.";
                break;
        }
    }


    if (result_http_code === undefined)
    {
        if (message_status_code >= 400 && message_status_code < 600)
            result_http_code = message_status_code;
        else
            result_http_code = 500;

        if (!detailed_msg)
            detailed_msg = context.getVariable("error.reason.phrase");
    }


    // Quota headers
    if (settingQuotaLimitHeaders)
    {
        var apptype = context.getVariable('clientAuth.AppType');
        if (apptype == 'confidential' || apptype == 'm2m')
        {
            var expirytime = context.getVariable('ratelimit.QU-QuotaCheck.expiry.time') || context.getVariable('ratelimit.QU-UserQuotaCheck.expiry.time');
            if (expirytime)
                context.setVariable('message.header.X-Rate-Limit-Reset', expirytime);
        }
    }



    if (returningBlankBody || initial_verb == "OPTIONS" || initial_verb == "HEAD")
    {
        context.setVariable('message.content', "");
    }
    else if (returningPayloadAsIs)
    {
        print('errorhandling.returningPayloadAsIs: true');
    }
    else
    {
        //var customfault_details = context.getVariable("customfault.details");
        print('errorhandling.checkingPayloadForCompability: ' + checkingPayloadForCompatibility);
        print('errorhandling.attemptingParse: ' + attemptingPayloadParse);

        if (checkingPayloadForCompatibility && readPayload() && checkIsPayloadCompatible())
            print('errorhandling.keepingCurrentPayload: true');
        else
        {
            if (attemptingPayloadParse && /*!bodyAlreadyParsed &&*/ parsePayload())
                print('errorhandling.payloadParsed: true');
            composePayload(result_http_code, detailed_msg);
            print('errorhandling.payloadComposed: true');
            print('xxxxxxxxxxxxxxxxxx: result_http_code: '+result_http_code);
        }
    }


    //context.setVariable('flow.error.status', result_http_code);
    //context.setVariable('flow.error.code', result_http_code);
    //context.setVariable('flow.error.reason', getMessageForCode(result_http_code));
    //context.setVariable('flow.error.message', detailed_msg);

    //context.setVariable('flow.error.content.type', 'application/json');
    //context.setVariable('flow.error.info', 'https://api.claro.com.br/docs');


}
catch (e)
{
    if (result_http_code === null) result_http_code = 500;
    context.setVariable('message.content', "");
    context.setVariable('message.header.Content-Type', 'application/json');
    throw e;
}
finally
{
    context.setVariable('message.status.code', result_http_code);
}


function readPayload()
{
    var contentType = context.getVariable('message.header.Content-Type');

    if (contentType === null)
        return false;

    var part = (context.error !== undefined ? context.error : (response !== undefined ? response : (request !== undefined ? request : null)));
    var content = part.content;

    if (content.length <= 0)
        return false;

    isJson = (!contentType.includes("/xml"));
    if (isJson)
        json = content.asJSON;
    else
        xml = content.asXML;

    return true;
}


function parsePayload()
{
    print('parsePayload...');

    if (!json && !xml)
        return false;

    if (curr_error_code || curr_detailed_msg) // API as backend
    {
        if (curr_detailed_msg && curr_detailed_msg.length > 0)
            detailed_msg = getDetailedMsg(curr_detailed_msg);

        if (curr_result_http_code && curr_result_http_code.length == 3 && curr_result_http_code >= 400 && curr_result_http_code < 600)
            result_http_code = curr_result_http_code;
        else if (curr_error_code)
        {
            print('curr_error_code:'+curr_error_code);
            const apiHttpCodeFromErrorCodeRegex = /\w+-(\d{3})/;
            var match = apiHttpCodeFromErrorCodeRegex.exec(curr_error_code);
            if (match !== null && match.length > 1)
                result_http_code = match[1];
        }
        return true;
    }

    if (json)
    {
        return false;
    }
    else // xml
    {
        return false;
    }
}


function composePayload(result_http_code, detailed_msg)
{
    if (isSoap())
    {
        composeSoap11Payload(result_http_code, detailed_msg);
        return;
    }
    else if(isLegacy()){

        var errorCodeStart = getErrorCodeStart();
        var apiDomain = errorCodeStart.split('-')[1];

        if (apiDomain == "PROVISIONINGPRODUCTORDERS" || apiDomain == "PROVISIONINGPRODUCTEVENTS"){

            composeProvisioningProductPayload(result_http_code);
            return;
        }
        else if (apiDomain.indexOf("TROUBLETICKET") >= 0)
        {
            composeTroubleTicketPayload(result_http_code, apiDomain);
            return;
        }
        else if (apiDomain == "NYACCOUNT")
        {
            composeAccountsPayload();
            return;
        }
        else if (apiDomain == "NYEVENTNIO")
        {
            composeEventNioPayload();
            return;
        }
        else if (apiDomain == "NYSUBSCRIPTIONSTOKENS")
        {
            composeNyPayload();
            return;
        }

    }

    var transactionId = context.getVariable('transactionId');
    var apiVersion = context.getVariable('apiVersion');

    var body = {};
    body.apiVersion = apiVersion;
    body.transactionId = transactionId;

    body.error = {};
    body.error.httpCode = result_http_code;
    body.error.errorCode = getErrorCode(result_http_code);
    print('getMessageForCode(result_http_code): ' + getMessageForCode(result_http_code));
    print('result_http_code: ' + result_http_code);
    body.error.message = getMessageForCode(result_http_code);
    body.error.detailedMessage = detailed_msg;
    body.error.link = {};
    body.error.link.rel = "related";
    body.error.link.href = "https://api.claro.com.br/docs";

    //throw new Exception();

    //context.setVariable('message.content', JSON.stringify(body));
    if (context.error)
        context.error.content = JSON.stringify(body);
    else
        response.content = JSON.stringify(body);
    context.setVariable('message.header.Content-Type', 'application/json;charset=UTF-8');
    context.setVariable('errorhandling.payloadOverwritten', 'true');
}


function composeSoap11Payload(result_http_code, detailed_msg)
{
    var body = '<?xml version="1.0" encoding="UTF-8" standalone="no"?><soapenv:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header/><soap-env:Body xmlns:soap-env="http://schemas.xmlsoap.org/soap/envelope/"><soap-env:Fault><faultcode>' + result_http_code + '</faultcode><faultstring>' + getMessageForCode(result_http_code) + '</faultstring><detail>' + detailed_msg + '</detail></soap-env:Fault></soap-env:Body></soapenv:Envelope>';

    if (context.error)
        context.error.content = body;
    else
        response.content = body;
    context.setVariable('message.header.Content-Type', 'text/xml');
    context.setVariable('errorhandling.payloadOverwritten', 'true');
}

function composeProvisioningProductPayload(result_http_code)
{
    var category = "TECNICO";
    var id = "TE-000001";
    var message = "Ocorreu uma falha técnica não esperada";
    var instruction = "Por favor, aguarde alguns instantes e tente novamente, persistindo o problema entre em contato com o suporte técnico informando esta mensagem";
    var reason = "Por favor aguarde alguns instantes e tente novamente, persistindo o problema, entre em contato com o suporte técnico informando esta mensagem";

    switch (result_http_code)
    {
        case 401:
            category = "SEGURANCA";
            id = "SE-000401";
            message = "Autenticação Negada";
            instruction = "Verifique as credenciais de acesso utilizadas pela aplicação";
            reason = "Verifique as credenciais de acesso utilizadas pela aplicação";
            break;
    }

    if (error.content != null && error.content.indexOf("categoria") <= 0)
    {
        var body = '{"erro": { "categoria": "'+category+'","id": "'+id+'",	"codigo": "'+result_http_code+'", "mensagem": "'+message+'","instrucao": "'+instruction+'","motivo": "'+reason+'"}}';

        if (context.error)
            context.error.content = body;
        else
            response.content = body;
    }

    context.setVariable('errorhandling.payloadOverwritten', 'true');
}

function composeTroubleTicketPayload(result_http_code, apiDomain)
{
    var code = "022";
    var error_code = "";
    var message = "Internal Server Error";
    var type = "Technical Error";
    var transactionId = context.getVariable('transactionId');

    switch (result_http_code)
    {
        case 401:
            message = "Unauthorized user";
            type = "Invalid parameter";
            code = "002";
            break;
        case 403:
            message = "Access denied";
            type = "Invalid parameter";
            code = "003";
            break;
        case 429:
            message = "Consumer requests exceeded policies";
            type = "Technical Error";
            code = "009";
            break;
    }

    switch (apiDomain)
    {
        case "TROUBLETICKETEVENT":
            error_code = "API-TROUBLE-TICKET-EVENT-" + code;
            break;
        case "TROUBLETICKET":
            error_code = "API-TROUBLE-TICKET-" + code;
            break;
        case "TROUBLETICKETATTACHMENTEVENT":
            error_code = "API-TROUBLETICKETATTACHMENTEVENT-" + code;
            break;
        case "TROUBLETICKETATTACHMENT":
            error_code = "API-TROUBLE-TICKET-ATTACHMENT-" + code;
            break;
    }

    if (error.content != null && error.content.indexOf("reason") <= 0)
    {
        var body = '{ "apiVersion": "1", "correlationId": "'+transactionId+'", "code": "'+result_http_code+'", "reason": "'+error_code+'", "message": "'+message+'", "status": "'+result_http_code+'", "referenceError": "'+result_http_code+'", "type": "'+type+'", "schemaLocation": "https://api.claro.com.br/docs" }';

        if (context.error)
            context.error.content = body;
        else
            response.content = body;
    }

    context.setVariable('errorhandling.payloadOverwritten', 'true');
}

function composeAccountsPayload()
{
    var error_message = "";
    switch (result_http_code)
    {
        case 401:
        case 403:
            result_http_code = 401;
            error_message = '{"Error": {"HttpStatusCode": 401,"ErrorCode": "BadAuthorization","ErrorDescription": "Authorization failed"}}';
            break;
        case 500:
        case 429:
            result_http_code = 500;
            error_message = '{"Error": {"HttpStatusCode": 500,"ErrorCode": "ServerError","ErrorDescription": "Try call again later."}}';
            break;
        case 503:
            error_message = '{"Error": {"HttpStatusCode": 503,"ErrorCode": "ServiceUnavailable","ErrorDescription": "Cannot process request, try again later"}}';
            break;
    }

    if (error.content != null && error.content.indexOf("Error") <= 0)
    {
        if (context.error)
            context.error.content = error_message;
        else
            response.content = error_message;
    }

    context.setVariable('errorhandling.payloadOverwritten', 'true');
}

function composeEventNioPayload()
{
    var error_message = "";
    switch (result_http_code)
    {
        case 401:
            error_message = '{"Error": {"HttpStatusCode": 401,"ErrorCode": "BadAuthorization","ErrorDescription": "Unauthorized"}}';
            break;
        case 403:
            error_message = '{"Error": {"HttpStatusCode": 403,"ErrorCode": "BadAuthorization","ErrorDescription": "Access denied"}}';
            break;
        case 429:
            error_message = context.getVariable("request.content");
            break;
        case 503:
            error_message = '{"Error": {"HttpStatusCode": 503,"ErrorCode": "ServiceUnavailable","ErrorDescription": "Cannot process request, try again later"}}';
            break;
    }

    if ((error.content != null && error.content.indexOf("Error") <= 0) || result_http_code == 429)
    {
        if (context.error)
            context.error.content = error_message;
        else
            response.content = error_message;
    }

    context.setVariable('errorhandling.payloadOverwritten', 'true');
}

function composeNyPayload()
{
    var error_message = "";
    switch (result_http_code)
    {
        case 401:
            error_message = '{"Error": {"HttpStatusCode": 401,"ErrorCode": "BadAuthorization","ErrorDescription": "Unauthorized"}}';
            break;
        case 403:
            //result_http_code = 401;
            error_message = '{"Error": {"HttpStatusCode": 403,"ErrorCode": "Forbidden","ErrorDescription": "Forbidden"}}';
            break;
        case 429:
            //result_http_code = 500;
            //error_message = '{"Error": {"HttpStatusCode": 500,"ErrorCode": "ServerError","ErrorDescription": "Try call again later"}}';
            error_message = '{"Error": {"HttpStatusCode": 429,"ErrorCode": "TooManyRequests","ErrorDescription": "Too Many Requests"}}';
            break;
        case 503:
            error_message = '{"Error": {"HttpStatusCode": 503,"ErrorCode": "ServiceUnavailable","ErrorDescription": "Cannot process request, try again later"}}';
            break;
    }

    if (error.content != null && error.content.indexOf("Error") <= 0)
    {
        if (context.error)
            context.error.content = error_message;
        else
            response.content = error_message;
    }

    context.setVariable('errorhandling.payloadOverwritten', 'true');
}

function checkIsPayloadCompatible()
{
    //var content = context.getVariable('message.content');
    //var content = msg.content;

    //var part = (context.error !== undefined ? context.error : (response !== undefined ? response : (request !== undefined ? request : null)));
    //var content = part.content;
    //var content = context.getVariable('message.content');

    //if (part === null)// || part.content === null || part.content.length <= 0)
    //  return false;

    //var content = part.content;
    //var json = content.asJSON;

    if (!json && !xml)
        return false;

    //var json;
    //try { json = JSON.parse(content); } catch (e) { }
    //var json = content.asJSON;

    //var json = content.body.asJSON;
    //context.setVariable('json', JSON.stringify(body));
    if (json)
    {
        if (json.error)
        {
            curr_result_http_code = json.error.httpCode;
            curr_error_code = json.error.errorCode;
            curr_message = json.error.message;
            curr_detailed_msg = json.error.detailedMessage;
        }
    }
    else
    {
        print('xml');
        //var xml = context.error.content.asXML;
        //var xml = content.asXML;
        //var xml = context.getVariable('message.content.asXML');
        if (xml !== undefined)
        {
            print('ifxml');
            if (xml.error !== null)
            {
                print('ifxmlerror');
                curr_result_http_code = xml.error.httpCode.toString();
                curr_error_code = xml.error.errorCode.toString();
                curr_message = xml.error.message.toString();
                curr_detailed_msg = xml.error.detailedMessage.toString();
            }
        }
    }

    print(curr_result_http_code, '|', curr_error_code, '|', curr_detailed_msg);

    var error_code_match = (curr_error_code && /*curr_error_code.startsWith(getErrorCode(result_http_code)))*/
        typeof curr_error_code === 'string' &&
        (isLegacy() || curr_error_code.startsWith(getErrorCodeStart())));
    var http_code_match = (curr_result_http_code && curr_result_http_code == result_http_code);

    print('http_code_match:',http_code_match);
    print('error_code_match:',error_code_match);

    if (http_code_match && error_code_match)
        return true;
    else if (error_code_match && result_http_code == 500 && curr_result_http_code && curr_result_http_code.length == 3)
    {
        result_http_code = curr_result_http_code;
        return true;
    }

    print('checkIsPayloadCompatible: false');
    return false;
}

var _errorCodeStart;
function getErrorCodeStart()
{
    if (_errorCodeStart !== undefined) return _errorCodeStart;

    const apiDomainRegex = /([A-Za-z]+)-v\d+[\w-]*/;
    var apiproxy_name = context.getVariable('apiproxy.name');
    var match = apiDomainRegex.exec(apiproxy_name);
    var apiDomain = (match !== null && match.length > 1 ? match[1] : apiproxy_name).toUpperCase();
    return _errorCodeStart = 'API-' + apiDomain + '-';
}


var _isLegacy;
function isLegacy()
{
    if (_isLegacy !== undefined) return _isLegacy;
    var apiproxy_name = context.getVariable('apiproxy.name');
    return (_isLegacy = (apiproxy_name.startsWith('domains-') || apiproxy_name.startsWith('soap-')));
}

function isSoap()
{
    var apiproxy_name = context.getVariable('apiproxy.name');
    return (apiproxy_name.startsWith('soap-'));
}


// function getErrorCode(code)
// {
//     return getErrorCodeStart() + code;
// }
var overrideForbidden = false;
var override429Code = null;
var overrideTooManyRequests = false;
var overrideErrorCodeProposals = false;
function getErrorCode(code)
{
    var errorCodeStart = getErrorCodeStart();

    // Legacy treatment - should be migrated to external config soon
    if (isLegacy())
    {
        var apiDomain = errorCodeStart.split('-')[1];
        const map =
            {
                "ADDRESSES": "ADDRESS",
                "ADDRESSESCITIES": "ADDRESSES",
                "ADDRESSESGEDDOMICILES": "ADDRESSES",
                "ADDRESSESGED": "ADDRESSES",
                "ADDRESSESPOSTALOFFICEBOXES": "ADDRESSES",
                "ADDRESSESPUBLICPLACES": "ADDRESSES",
                "ADDRESSESSTATES": "ADDRESSES",
                "AUTHORITYAUTHORIZATIONS": "AUTHORITYAUTHORIZATION",
                "BILLSDEBITS": "DEBITS",
                "BOOKINGSTATUS": "BOOKING",
                "BULKWORKORDERS": "TOA",
                "CANCELWORKORDERS": "CANCELWORKORDER",
                "CANDIDATES": "RECRUITMENTS",
                "CANDIDATESAPPROVALS": "RECRUITMENTS",
                "CANDIDATESDEPENDENTS": "RECRUITMENTS",
                "CANDIDATESELIGIBILITIES": "RECRUITMENTS",
                "CHANNELRECALLS": "RTDM",
                "COMMUNICATIONMANAGEMENTS": "COMMSG",
                "CONTESTATIONHISTORIES": "CONTESTATIONHISTORY",
                "CONTRACTPRODUCTS": "CONTRACT-PRODUCTS",
                "CORPORATECUSTOMERS": "MOBILECUSTOMERS",
                "CUSTOMERCONTRACTSSUBSCRIBERS": "CUSTOMERCONTRACTS",
                "CUSTOMERSPRODUCTSPPVS": "CUSTOMER-PRODUCTS",
                "CUSTOMERSVALUEADDSERVICES": "CUSTOMERS-VAS",
                "DOCUMENTSCONTRACTS": "DOCSCONTRACTS",
                "DOMICILIESHISTORIES": "ADDRESSES",
                "ECOMMERCEADITIONALDATAS": "VENDAECOMMERCEMIGRACAODADOSADICIONAISLISTAR",
                "ECOMMERCECLIENTIDENTIFIES": "VENDAECOMMERCEMIGRACAOCLIENTECADASTROIDENTIFICAR",
                "ECOMMERCEIDENTIFIES": "VENDAECOMMERCEMIGRACAOIDENTIFICAR",
                "EMPLOYERJOBSCANDIDATES": "OCCUPATIONALHEALTHSAFETIES",
                "EMPLOYEES": "OCCUPATIONALHEALTHSAFETIES",
                "EMPLOYEESCANDIDATES": "OCCUPATIONALHEALTHSAFETIES",
                "EMPLOYEESMEDICALEXAMS": "OCCUPATIONALHEALTHSAFETIES",
                "EMPLOYEESMEDICALRECORDS": "OCCUPATIONALHEALTHSAFETIES",
                "EMPLOYEESMEDICINECERTIFICATES": "OCCUPATIONALHEALTHSAFETIES",
                "EMPLOYEESTECHNICIANS": "EMPLOYEES",
                "EMPLOYEESTRAININGS": "OCCUPATIONALHEALTHSAFETIES",
                "FORWARDINGRECOMMENDATIONS": "RTDM",
                "GEOGRAPHICLOCATIONS": "GEOLOC",
                "HISTORICALINVOICES": "INVOICE",
                "HISTORYPROPOSALS": "HISTORYPROPOSAL",
                "INTERACTIONMENUS": "INTERACTIONMENU",
                "LOYALTYAUCTIONBIDSHIGHEST": "LOYALTYHIGHESTAUCTIONBIDS",
                "LOYALTYAUCTIONSCUSTOMERSBIDPOINTS": "LOYALTYHIGHESTAUCTIONBIDS",
                "LOYALTYCUSTOMEREMAILS": "LOYALTYCUSTOMERSEMAILS",
                "LOYALTYCUSTOMERSREWARDS": "LOYALTYHIGHESTAUCTIONBIDS",
                "LOYALTYREDEMPTIONS": "LOYALTYREDEMPTIONSEMAILCONFIRMATIONS",
                "LOYALTYPROMOTIONSSEGMENTATIONS": "LOYALTYPROMOTIONSPRODUCTS",
                "MAPSERVERS": "ARCGIS",
                "NEGOTIATIONHISTORIES": "NEGOCIOATIONHISTORY",
                "NETWORKTOPOLOGIES": "TOPOLOGY",
                "NOTIFICATIONSORDERSTATUS": "NOTIFICATIONS",
                "NYSTREAMINGCHARGESRESULT":"STREAMINGCHARGESRESULT",
                "NYSTREAMINGSUBSCRIPTIONS": "STREAMINGSUBSCRIPTIONS",
                "NYSTREAMINGSUBSCRIPTIONSSTATUS": "STREAMINGSUBSCRIPTIONSSTATUS",
                "ORDERSCONFIGURATIONS": "ORDCONF",
                "ORDERSREQUESTS": "ORDREQ",
                "ORDERSWORKORDERS": "ORDWRK",
                "OUTAGESNOTIFICATIONS": "OUTAGES",
                "PDFINVOICES": "INVOICESPDF",
                "PORTABILITYOPERATOR": "PORTABILITY",
                "PORTABILITIESPREANALYSIS": "PortabilitiesPreanalysis",
                "PORTABILITYWINDOWS": "PORTABILITY",
                "PROMOTIONBENEFITSSUBSCRIBER": "MOBILESUBSCRIBERSHISTORY",
                "PROMOTIONSHISTORIES": "PROMOTIONSHISTORY",
                "PROMOTIONSSUBSCRIBERS": "PROMOTIONSSUBSCRIBER",
                "PROPOSALS": "PROPOSAL",
                "PROVISIONINGORDERS": "PROVISIONING-ORDERS",
                "PROVISIONINGORDERSRESULTS": "PROVISIONING-ORDERS-CALLBACK",
                "RESCHEDULING": "WORKORDERSCHEDULESSCHEDULING",
                "RECOMMENDATIONSACCOUNTPLANS": "RECOMMENDATION",
                "SALESALERTS": "SALESALERTLIST",
                "SALESMENRESIDENTIAL": "SALESMEN",
                "SALESORDERSMOBILES": "SALESORDERMOBILE",
                "SERVICESUSERSINACTIVES": "SERVICESUSERS",
                "SCHEDULESERVICES": "TOA",
                "SERVICEUSEROTPS": "OTP",
                "SIMPLIFIED": "CREDITANALYSIS",
                "SOLICITATIONS": "PORTABILITY",
                "STATUS": "FRAUDSEVALUATION",
                "SUBSCRIBERLASTDEVICES": "SUBSCRIBERLASTDEVICE",
                //"SUBSCRIBERREQUESTS": "SUBSCRIBERREQUEST", // Rolled-back as requested by Tanabe/Charles
                "SUBSCRIBERVAS": "SUBSCRIVERVAS", // Original typo
                "TELEPHONENUMBERS": "TELEPHONENUMBERSRESERVATIONS",
                "TOAACTIVITIES": "ACTIVITIES",
                "TOARESOURCES": "ROUTES",
                "TOATECHNICIANS": "TECHNICIANS",
                "TOAUSERS": "ACTIVITIES",
                "TOKENS": "TOKEN",
                "WINDOWS": "PORTABILITY",
                "WORKOPPORTUNITES": "RECRUITMENTS",
                "WORKOPPORTUNITIESCANCELLATIONS": "RECRUITMENTS",
                "WORKOPPORTUNITESDETAILS": "RECRUITMENTS",
                "WORKORDERSCHEDULESAVAILABILITY": "API-WORKORDERSCHEDULESAVAILABILITY"
            };

        if(context.getVariable('apiproxy.name').toUpperCase().indexOf("PRODUCTORDERS-CUSTOMERS") >= 0){

            errorCodeStart = "API-PRODUCTORDERS-CUSTOMERS-";
            apiDomain = "PRODUCTORDERS-CUSTOMERS";
        }
        else if(context.getVariable('apiproxy.name').toUpperCase().indexOf("PRODUCTORDERS-VALUEADDSERVICES") >= 0){

            errorCodeStart = "API-PRODUCTORDERS-VAS-";
            apiDomain = "PRODUCTORDERS-VAS";

            if (code == 401)
                code = "003";
            else if (code == 403)
                code = "004";
            else if (code == 429)
                code = "030";
        }
        else if(context.getVariable('apiproxy.name').toUpperCase().indexOf("PRODUCTORDERS-VALUEADDSERVICESPINCODES") >= 0){

            errorCodeStart = "API-PRODUCTORDERS-VAS-";
            apiDomain = "PRODUCTORDERS-VAS";

            if (code == 401)
                code = "003";
            else if (code == 403)
                code = "004";
            else if (code == 429)
                code = "030";
        }
        else if(context.getVariable('apiproxy.name').toUpperCase().indexOf("SERVICECANDIDATES-VALUEADDSERVICES") >= 0){

            errorCodeStart = "API-SERVICECANDIDATES-VAS-";
            apiDomain = "SERVICECANDIDATES-VAS";

            if (code == 401)
                code = "003";
            else if (code == 403)
                code = "004";
            else if (code == 429)
                code = "030";
        }
        else if(context.getVariable('apiproxy.name').toUpperCase().indexOf("SERVICECATEGORIES-VALUEADDSERVICES") >= 0){

            errorCodeStart = "API-SERVICECATEGORIES-VAS-";
            apiDomain = "SERVICECATEGORIES-VAS";

            if (code == 401)
                code = "003";
            else if (code == 403)
                code = "004";
            else if (code == 429)
                code = "030";
        }
        else if(context.getVariable('apiproxy.name').toUpperCase().indexOf("FRAUDS-EVALUATIONS") >= 0){

            if(context.getVariable('apiproxy.name').toUpperCase().indexOf("FRAUDS-EVALUATIONS-V") >= 0){

                errorCodeStart = "API-FRAUDS-SEND-";
                apiDomain = "FRAUDS-SEND";
            }
            else{

                errorCodeStart = "API-" + (errorCodeStart.indexOf("AUTHENTICATIONS") >= 0 ? "FRAUDSAUTH-" : "FRAUDSEVALUATION-");
                overrideForbidden = true;
            }
        }
        else if (map.hasOwnProperty(apiDomain)){

            errorCodeStart = "API-" + map[apiDomain] + "-";
        }
        else if (apiDomain == "SUBSCRIBERS" || apiDomain == "OFFERS"){

            overrideErrorCodeProposals = true;
            var errorCodeStart = apiDomain == "SUBSCRIBERS" ? "API-PROPOSALSSUBSCRIBERS-" : "API-PROPOSALSOFFERSVALIDATIONS-";

            if (code == 401 || code == 429)
                code = "06";
            else if (code == 403)
                code = "002";
        }
        else if (apiDomain == "INTERACTIONS")
        {
            if (context.getVariable("request.content").indexOf("companyId") >= 0){
                errorCodeStart = "API-INT-";
            }
            else
            {
                errorCodeStart = "API-INTERACTIONS-";
                overrideForbidden = true;
                overrideTooManyRequests  = true;
            }
        }
        else if (apiDomain == "CUSTOMERSSUBSCRIBEROFFERS"){

            errorCodeStart = "API-SUBSCRIBEROFFERS-";
            apiDomain = "SUBSCRIBEROFFERS";

            if (code == 401)
                code = "003";
            else if (code == 403)
                code = "004";
            else if (code == 429)
                code = "010";
        }

        if (code == 401 || code == 403 || code == 429 ||
            code == 400 && ['ThreateningContentValidation','SizeLimitCheck','PayloadSizeUpperLimitCheck'].indexOf(customfault_name) >= 0)
        {
            switch (apiDomain)
            {
                case "ADDRESSESCITIES":
                case "ADDRESSESSTATES":
                case "ADDRESSESPUBLICPLACES":
                case "ADDRESSESPOSTALOFFICEBOXES":
                case "CHANNELRECALLS":
                case "CUSTOMERSVALUEADDSERVICES":
                case "FORWARDINGRECOMMENDATIONS":
                case "LOYALTYAUCTIONSCUSTOMERSBIDPOINTS":
                case "LOYALTYCUSTOMERSREWARDS":
                case "LOYALTYPROMOTIONSPRODUCTS":
                case "LOYALTYPROMOTIONSSEGMENTATIONS":
                    overrideForbidden = true;
                    break;

                case "BANKSACCOUNTSVALIDATIONS":
                case "SALESORDERSMOBILES":
                    override429Code = "010";

                case "BALANCES":
                case "GEOGRAPHICLOCATIONSVIABILITIES":
                case "MOBILECUSTOMERS":
                case "MOBILESUBSCRIBERS":
                case "MOBILESUBSCRIBERSHISTORY":
                case "PORTABILITIESPREANALYSIS":
                case "PORTABILITYWINDOWS":
                case "PROMOTIONBENEFITSSUBSCRIBER":
                case "TELEPHONENUMBERS":
                case "TELEPHONENUMBERSRESERVATIONS":
                case "WINDOWS":
                    override429Code = override429Code || "008";
                case "ADDRESS":
                case "ADDRESSES":
                case "ADDRESSESPROPERTIES":
                case "ADDRESSESGEDDOMICILES":
                case "BILLINGCYCLES":
                case "BOOKINGSTATUS":
                case "CASES":
                case "COMMUNICATIONMANAGEMENTS":
                case "CONTRACTPRODUCTS":
                case "CONTRACTSCOLLECTIONINFO":
                case "CORPORATECUSTOMERS":
                case "CREDITANALYSIS":
                case "GEOGRAPHICLOCATIONS":
                case "HISTORICALINVOICES":
                case "HISTORYPROPOSALS":
                case "INTERACTIONS":
                case "PRODUCTS":
                case "PROMOTIONSHISTORIES":
                case "PROMOTIONSSUBSCRIBERS":
                case "PROVISIONINGORDERSRESULTS":
                case "RESCHEDULING":
                case "SALESALERTS":
                case "SALESORDERS":
                case "SERVICEUSEROTPS":
                case "SUBSCRIBERLASTDEVICES":
                //case "SUBSCRIBERREQUESTS": // Rolled-back as requested by Tanabe/Charles
                case "SUBSCRIBERVAS":
                case "TRANSACTIONHISTORY":
                case "USAGEMOBILES":
                case "WORKORDERSCHEDULES":
                case "WORKORDERSCHEDULESAVAILABILITY":
                    overrideForbidden = true;
                case "ADDRESSESBUILDINGS":
                case "ADDRESSESGED":
                case "BILLSDEBITS":
                //case "CONTACTRECORDS": // Rolled-back as requested by Tanabe/Charles
                case "CANDIDATES":
                case "CANDIDATESAPPROVALS":
                case "CANDIDATESDEPENDENTS":
                case "CANDIDATESELIGIBILITIES":
                case "DOMICILIESHISTORIES":
                case "EMPLOYEES":
                case "EMPLOYEESCANDIDATES":
                case "EMPLOYEESMEDICALEXAMS":
                case "EMPLOYEESMEDICALRECORDS":
                case "EMPLOYEESMEDICINECERTIFICATES":
                case "EMPLOYEESTECHNICIANS":
                case "EMPLOYEESTRAININGS":
                case "FRAUDS-SEND":
                case "IDENTIFYOPERATOR":
                case "INTERACTIONS":
                case "MAPSERVERS":
                case "NOTIFICATIONSORDERSTATUS":
                case "OCTANE":
                case "ORDERSCONFIGURATIONS":
                case "ORDERSREQUESTS":
                case "ORDERSWORKORDERS":
                case "PDFINVOICES":
                case "PORTABILITY":
                case "PORTABILITYOPERATOR":
                case "PRODUCTORDERS-CUSTOMERS":
                case "PROPOSALS":
                case "PROPOSAL":
                case "RECOMMENDATIONSACCOUNTPLANS":
                case "REQUESTS":
                case "SALESDOCUMENTS":
                case "SALESMEN":
                case "SALESMENRESIDENTIAL":
                case "SALESORDERS":
                case "SERVICESUSERSINACTIVES":
                case "SHOPPINGCARTS":
                case "SIMPLIFIED":
                case "SOLICITATIONS":
                case "TOAACTIVITIES":
                case "TOARESOURCES":
                case "TOATECHNICIANS":
                case "TOAUSERS":
                case "TOKENS":
                case "WORKOPPORTUNITES":
                case "WORKOPPORTUNITIESCANCELLATIONS":
                case "WORKOPPORTUNITESDETAILS":
                    switch (code.toString())
                    {
                        case "400":
                            code = "001";
                            break;
                        case "401":
                            code = "002";
                            break;
                        case "403":
                            code = "003";
                            break;
                        case "429":
                            code = override429Code || "009";
                            break;
                    }
            }

            switch (apiDomain)
            {
                case "BANKSACCOUNTSVALIDATIONS":
                    overrideForbidden = false;
                    break;

                case "ADDRESSESCITIES":
                case "ADDRESSESPOSTALOFFICEBOXES":
                case "CANCELWORKORDERS":
                case "CONTRACTSCOLLECTIONINFO":
                case "GEOGRAPHICLOCATIONS":
                case "GEOGRAPHICLOCATIONSVIABILITIES":
                case "HISTORYPROPOSALS":
                case "HISTORICALINVOICES":
                case "LOYALTYAUCTIONBIDS":
                case "LOYALTYAUCTIONBIDSHIGHEST":
                case "LOYALTYAUCTIONSCUSTOMERSBIDPOINTS":
                case "LOYALTYCUSTOMERSREWARDS":
                case "LOYALTYPROMOTIONSPRODUCTS":
                case "LOYALTYPROMOTIONSSEGMENTATIONS":
                case "MAPSERVERS":
                case "OTPCHANNELS":
                case "PDFINVOICES":
                case "PROMOTIONBENEFITSSUBSCRIBER":
                case "PROMOTIONSHISTORIES":
                case "PROVISIONINGORDERSRESULTS":
                case "RESCHEDULING":
                case "SERVICESUSERSINACTIVES":
                case "SIMPLIFIED":
                case "SUBSCRIBERVAS":
                case "SOLICITATIONS":
                case "TELEPHONENUMBERS":
                case "TOKENS":
                case "TRANSACTIONHISTORY":
                case "USAGEMOBILES":
                case "WINDOWS":
                case "WORKORDERSCHEDULES":
                case "WORKORDERSCHEDULESAVAILABILITY":
                    overrideTooManyRequests  = true;
            }
        }
    }

    return errorCodeStart + code;
}


function getMessageForCode(code)
{
    switch (parseInt(code, 10))
    {
        case 400:
            return "Bad Request";
        case 401:
            if (overrideErrorCodeProposals) return "Service Unavailable";
            return "Unauthorized";
        case 403:
            if (overrideForbidden) return "Access denied";
            else if (overrideErrorCodeProposals) return "Invalid credentials";
            return "Forbidden";
        case 404:
            return "Not Found";
        case 405:
            return "Method Not Allowed";
        case 406:
            return "Not Acceptable";
        case 409:
            return "Conflict";
        case 410:
            return "Gone";
        case 413:
            return "Request Entity Too Large";
        case 414:
            return "Request-URI Too Large";
        case 415:
            return "Unsupported Media Type";
        case 422:
            return "Unprocessable Entity";
        case 429:
            if (overrideTooManyRequests) return "Consumer requests exceeded policies";
            else if (overrideErrorCodeProposals) return "Service Unavailable";
            return "Too Many Requests";
        case 451:
            return "Unavailable For Legal Reasons";
        case 500:
            return "Internal Server Error";
        case 502:
            return "Bad Gateway";
        case 503:
            return "Service Unavailable";
        case 504:
            return "Gateway Timeout";
        default:
            return "Internal Server Error";
    }
}


function getDetailedMsg(curr_detailed_msg)
{
    if (!curr_detailed_msg)
        return curr_detailed_msg;

    const detailedMsgFilterRegex = /\.[A-Za-z]+Exception[:,]|\.java:\d+/;
    var isMatch = detailedMsgFilterRegex.test(curr_detailed_msg);
    if (isMatch)
        curr_detailed_msg = "[filtered exception]";

    if (!curr_detailed_msg.startsWith(backendStr))
        return backendStr + curr_detailed_msg;
    else
        return curr_detailed_msg;
}