import logging
import requests
import sys,traceback
import tradingapi_b.exceptions as ex
from tradingapi_b import __config__
from urllib.parse import urljoin

default_log = logging.getLogger("mconnect.log")
default_log.addHandler(logging.FileHandler("mconnect.log", mode='a'))

class MConnectB:
    _default_timeout = 7

    def __init__(self,api_key=None,access_Token=None,pool=None,timeout=None,debug=True,logger=default_log,disable_ssl=True): 
        self.api_key=api_key
        self.access_token=access_Token
        self.session_expiry_hook = None
        self.timeout = timeout or self._default_timeout
        self.disable_ssl = disable_ssl
        self.debug=debug
        self.logger=logger

        #Read config.json and assign
        
        self.default_root_uri=__config__.default_root_uri
        self.routes=__config__.routes

        # Create requests session by default
        # Same session to be used by pool connections
        self.request_session = requests.Session()
        if pool:
            request_adapter = requests.adapters.HTTPAdapter(**pool)
            self.request_session.mount("https://", request_adapter)

        # disable requests SSL warning
        requests.packages.urllib3.disable_warnings()

    def set_session_expiry_hook(self, method):
        """
        Set a callback hook for session (`TokenError` -- timeout, expiry etc.) errors.
        """
        if not callable(method):
            raise TypeError("Invalid input type. Only functions are accepted.")

        self.session_expiry_hook = method

    def login(self,user_id,password):
        '''
        Login with credentials and obtains 
        '''
        data={"clientcode":user_id,"password":password,"totp": "","state": ""}
        url = urljoin(self.default_root_uri, self.routes["login"])
        try:
            #Using session request
            login_response=self._post(
                route="login",
                params=data,
                is_json=True,
                content_type="application/json"
            )
        except Exception as e:
            type_, value_, traceback_ = sys.exc_info()
            stack_trace = traceback.format_exception(type_, value_, traceback_)
            self.logger.error(stack_trace)
            raise ex.GeneralException(stack_trace) 
        return login_response
    
    def set_api_key(self,api_key):
        """Set the API Key received after successful authentication and session generated"""
        self.api_key=api_key

    def set_access_token(self, access_token):
        """Set the `access_token` received after a successful authentication."""
        self.access_token = access_token

    def generate_session(self,_api_key,_request_token,_otp):
        if self.api_key is None:
            self.set_api_key(_api_key)
        data={"refreshToken":_request_token,"otp":_otp}
        try:
            #Using session request
            gen_session=self._post(
                route="generate_session",
                params=data,
                is_json=True,
                content_type="application/json"
            )
        except Exception as e:
            type_, value_, traceback_ = sys.exc_info()
            stack_trace = traceback.format_exception(type_, value_, traceback_)
            self.logger.error(stack_trace)
            raise e
        if "data" in gen_session.json():
            if gen_session.json()["data"]!=None and "jwtToken" in gen_session.json()["data"]:
                self.set_access_token(gen_session.json()["data"]["jwtToken"])
        return gen_session

    def place_order(self,_variety,_tradingsymbol,_symboltoken,_exchange,_transactiontype,_ordertype,_quantity,_producttype,_price,_triggerprice,_squareoff,_stoploss,_trailingStopLoss,_disclosedquantity,_duration,_ordertag):
        order_packet={"variety":_variety,"tradingsymbol":_tradingsymbol,"symboltoken":_symboltoken,"exchange":_exchange,"transactiontype":_transactiontype,"ordertype":_ordertype,"quantity":_quantity,"producttype":_producttype,"price":_price,"triggerprice":_triggerprice,"squareoff":_squareoff,"stoploss":_stoploss,"trailingStopLoss":_trailingStopLoss,"disclosedquantity":_disclosedquantity,"duration":_duration,"ordertag":_ordertag}
        try:
            #Using session request
            order_session=self._post(
                route="place_order",
                params=order_packet,
                is_json=True,
                content_type="application/json"
            )
        except Exception as e:
            type_, value_, traceback_ = sys.exc_info()
            stack_trace = traceback.format_exception(type_, value_, traceback_)
            self.logger.error(stack_trace)
            raise e
        return order_session
       
    def modify_order(self,_variety,_orderid,_ordertype,_producttype,_duration,_price,_quantity,_tradingsymbol,_symboltoken,_exchange):
        url_args={"order_id": _orderid}
        #url = urljoin(self.default_root_uri, self.routes["modify_order"].format(**url_args))
        order_packet={"variety":_variety,"orderid": _orderid,"ordertype":_ordertype ,"producttype":_producttype,"duration":_duration,"price":_price,"quantity":_quantity,"tradingsymbol":_tradingsymbol ,"symboltoken": _symboltoken,"exchange": _exchange}
        try:
            #Using session request
            modify_session=self._put(
                route="modify_order",
                url_args=url_args,
                params=order_packet,
                is_json=True,
                content_type="application/json"
            )
        except Exception as e:
            type_, value_, traceback_ = sys.exc_info()
            stack_trace = traceback.format_exception(type_, value_, traceback_)
            self.logger.error(stack_trace)
            raise e
        return modify_session
    
    def cancel_order(self,_variety,_orderid):
        url_args={"order_id": _orderid}
        order_packet={"variety":_variety,"orderid":_orderid}
        try:
            #Using session request
            cancel_session=self._delete(
                route="cancel_order",
                url_args=url_args,
                params=order_packet,
                is_json=True,
                content_type="application/json"
            )
        except Exception as e:
            type_, value_, traceback_ = sys.exc_info()
            stack_trace = traceback.format_exception(type_, value_, traceback_)
            self.logger.error(stack_trace)
            raise e
        return cancel_session
    
    #New Endpoint
    def cancel_all(self):
        '''
        Method to cancel all the orders at once.
        '''
        try:
            #Using session request
            cancelAll_session=self._post(
                route="cancel_all",
                content_type="application/json"
            )
        except Exception as e:
            type_, value_, traceback_ = sys.exc_info()
            stack_trace = traceback.format_exception(type_, value_, traceback_)
            self.logger.error(stack_trace)
            raise e
        return cancelAll_session
    
    def get_order_book(self):
        try:
            #Using session request
            get_ord_book=self._get(
                route="order_book"
            )
        except Exception as e:
            type_, value_, traceback_ = sys.exc_info()
            stack_trace = traceback.format_exception(type_, value_, traceback_)
            self.logger.error(stack_trace)
            raise e
        return get_ord_book
    
    def get_net_position(self):
        try:
            #Using session request
            get_position=self._get(
                route="net_position",
                )
        except Exception as e:
            type_, value_, traceback_ = sys.exc_info()
            stack_trace = traceback.format_exception(type_, value_, traceback_)
            self.logger.error(stack_trace)
            raise e
        return get_position
    
    def calculate_order_margin(self,_product_type,_transaction_type,_quantity,_price,_exchange,_symbol_name,_token,_trigger_price):
        calc_data={"product_type":_product_type ,"transaction_type":_transaction_type ,"quantity": _quantity,"price": _price,"exchange": _exchange,"symbol_name": _symbol_name,"token": _token,"trigger_price": _trigger_price}
        try:
            #Using session request
            ord_margin=self._post(
                route="calculate_order_margin",
                params=calc_data,
                is_json=True,
                content_type="application/json"
            )
        except Exception as e:
            type_, value_, traceback_ = sys.exc_info()
            stack_trace = traceback.format_exception(type_, value_, traceback_)
            self.logger.error(stack_trace)
            raise e
        return ord_margin
    
    #New Endpoint
    def get_order_details(self,_order_id,_segment):
        '''
        Method to retrieve the status of individual order using the order id.
        '''
        details_packet={"order_no":_order_id,"segment":_segment}
        try:
            #Using session request
            get_ord_details=self._get(
                route="order_details",
                params=details_packet,
                is_json=True,
                content_type="application/json"
            )
        except Exception as e:
            type_, value_, traceback_ = sys.exc_info()
            stack_trace = traceback.format_exception(type_, value_, traceback_)
            self.logger.error(stack_trace)
            raise e
        return get_ord_details
    
    #New Endpoint
    def get_holdings(self):
        '''
        Method to retrieve all the list of holdings that contain the user's portfolio of long term equity delivery stocks.
        '''
        try:
            #Using session request
            get_holdings=self._get(
                route="holdings",
            )
        except Exception as e:
            type_, value_, traceback_ = sys.exc_info()
            stack_trace = traceback.format_exception(type_, value_, traceback_)
            self.logger.error(stack_trace)
            raise e
        return get_holdings
    
    def get_historical_chart(self,_exchange,_security_token,_interval,_fromDate,_toDate):
        request_packet={"exchange": _exchange,"symboltoken": _security_token,"interval": _interval,"fromdate": _fromDate,"todate": _toDate}
        try:
            #Using session request
            get_hist_chart=self._get(
                route="historical_chart",
                params=request_packet,
                is_json=True,
                content_type="application/json"
            )
        except Exception as e:
            type_, value_, traceback_ = sys.exc_info()
            stack_trace = traceback.format_exception(type_, value_, traceback_)
            self.logger.error(stack_trace)
            raise e
        return get_hist_chart
    
    def get_market_quote(self,_mode,_exchangeTokens):
        '''
        ohlc_input: List of strings in exchange:trading symbol format
        '''
        quote_details={"mode":_mode,"exchangeTokens":_exchangeTokens}
        try:
            #Using session request
            get_quote_data=self._get(
                route="market_quote",
                params=quote_details,
                is_json=True,
                content_type="application/json"
            )
        except Exception as e:
            type_, value_, traceback_ = sys.exc_info()
            stack_trace = traceback.format_exception(type_, value_, traceback_)
            self.logger.error(stack_trace)
            raise e
        return get_quote_data
    
    def get_instruments(self):
        try:
            #Using session request
            get_instrument=self._get(
                route="instrument_scrip",
            )
        except Exception as e:
            type_, value_, traceback_ = sys.exc_info()
            stack_trace = traceback.format_exception(type_, value_, traceback_)
            self.logger.error(stack_trace)
            raise e
        return get_instrument
    
    def get_fund_summary(self):
        try:
            get_fund_summary=self._get(
                route="fund_summary"
            )
        except Exception as e:
            type_, value_, traceback_ = sys.exc_info()
            stack_trace = traceback.format_exception(type_, value_, traceback_)
            self.logger.error(stack_trace)
            raise e
        return get_fund_summary
    
    def get_trade_history(self,_fromDate,_toDate):
        details_packet={"fromdate":_fromDate,"todate":_toDate}
        try:
            #Using session request
            get_trade=self._get(
                route="trade_history",
                params=details_packet,
                is_json=True,
                content_type="application/json"
            )
        except Exception as e:
            type_, value_, traceback_ = sys.exc_info()
            stack_trace = traceback.format_exception(type_, value_, traceback_)
            self.logger.error(stack_trace)
            raise e
        return get_trade

    def convert_position(self,_exchange,_symboltoken,_oldproducttype,_newproducttype,_tradingsymbol,_symbolname,_instrumenttype,_priceden,_pricenum,_genden,_gennum,_precision,_multiplier,_boardlotsize,_buyqty,_sellqty,_buyamount,_sellamount,_transactiontype,_quantity,_type):
        position_packet={"exchange": _exchange,"symboltoken": _symboltoken,"oldproducttype": _oldproducttype,"newproducttype": _newproducttype,"tradingsymbol": _tradingsymbol,"symbolname": _symbolname,"instrumenttype": _instrumenttype,"priceden": _priceden,"pricenum": _pricenum,"genden": _genden,"gennum": _gennum,"precision": _precision,"multiplier": _multiplier,"boardlotsize": _boardlotsize,"buyqty": _buyqty,"sellqty": _sellqty,"buyamount": _buyamount,"sellamount": _sellamount,"transactiontype": _transactiontype,"quantity": _quantity,"type": _type}
        try:
            #Using session request
            conv_position=self._post(
                route="position_conversion",
                params=position_packet,
                is_json=True,
                content_type="application/json"
            )
        except Exception as e:
            type_, value_, traceback_ = sys.exc_info()
            stack_trace = traceback.format_exception(type_, value_, traceback_)
            self.logger.error(stack_trace)
            raise e
        return conv_position
    
    def _get(self, route, url_args=None, content_type=None, params=None, is_json=False):
        """Alias for sending a GET request."""
        return self._request(route, "GET", url_args=url_args,content_type=content_type, params=params, is_json=is_json)

    def _post(self, route, url_args=None, content_type=None, params=None, is_json=False, query_params=None):
        """Alias for sending a POST request."""
        return self._request(route, "POST", url_args=url_args,content_type=content_type, params=params, is_json=is_json, query_params=query_params)

    def _put(self, route, url_args=None, content_type=None, params=None, is_json=False, query_params=None):
        """Alias for sending a PUT request."""
        return self._request(route, "PUT", url_args=url_args,content_type=content_type, params=params, is_json=is_json, query_params=query_params)

    def _delete(self, route, url_args=None, content_type=None, params=None, is_json=False):
        """Alias for sending a DELETE request."""
        return self._request(route, "DELETE", url_args=url_args,content_type=content_type, params=params, is_json=is_json)
    
    def _request(self, route, method, url_args=None, content_type="application/json",params=None, is_json=False, query_params=None):
        """Make an HTTP request."""
        # Form a restful URL
        if url_args:
            uri = self.routes[route].format(**url_args)
        else:
            uri = self.routes[route]

        url = urljoin(self.default_root_uri, uri)

        # Custom headers
        headers = {
            "X-Mirae-Version": "1",
            "Content-Type":str(content_type)
        }

        if self.api_key:
            headers["X-PrivateKey"]=self.api_key
        if self.access_token:
            # set authorization header
            headers["Authorization"] = "Bearer {}".format(self.access_token)

        #Adding to debug logs if flag set to true
        if self.debug:
            if is_json:
                self.logger.debug("Request: {method} {url} {json} {headers}".format(method=method, url=url, json=params, headers=headers))
            else:
                self.logger.debug("Request: {method} {url} {data} {headers}".format(method=method, url=url, data=params, headers=headers))
        
        
        
        ''''removed
Why? So the JSON body isn’t overwritten by URL query parameters.'''
        # prepare url query params
        # if method in ["GET", "DELETE"]:
        #     query_params = params

        try:
            response_data = self.request_session.request(method,
                                        url,
                                        # json=params if (method in ["POST", "PUT"] and is_json) else None,
                                        # data=params if (method in ["POST", "PUT"] and not is_json) else None,
                                        # params=query_params,
                                        # headers=headers,
                                        # verify=not self.disable_ssl,
                                        
                                        json=params if is_json else None,  # Use 'json' parameter regardless of method
                                        headers=headers,
                                        verify=not self.disable_ssl,
                                        allow_redirects=True,
                                        timeout=self.timeout)
        except Exception as e:
            raise e

        if self.debug:
            self.logger.debug("Response: {code} {content}".format(code=response_data.status_code, content=response_data.content))

        # Validate the content type.
        if "content-type" in response_data.headers:
            if "json" in response_data.headers["content-type"]:
                try:
                    data = response_data.json()
                    if type(data)==list:
                        data=data[0]
                except ValueError:
                    raise ex.DataException("Couldn't parse the JSON response received from the server: {content}".format(
                        content=response_data.content))
                
                # api error
                if "status" in data:
                    if data.get("status") == "false":
                        if "error_type" in data:
                            # Call session hook if its registered and TokenException is raised
                            if self.session_expiry_hook and response_data.status_code == 403 and data["error_type"] == "TokenException":
                                self.session_expiry_hook()
                    
                        if str(data["errorcode"])[0:2]=="MA":
                            #Raise Mirae Exception
                            raise ex.MiraeException(data["message"],str(data["errorcode"])[2:])
                        elif str(data["errorcode"])[0:2]=="IA":
                            raise ex.InteractiveAPIException(data["message"],str(data["errorcode"])[2:])
                        else:
                            raise ex.GeneralException(data["message"],str(data["errorcode"]))                                                     
            
            elif "csv" in response_data.headers["content-type"]:
                return response_data.content
            else:
                raise ex.DataException("Unknown Content-Type ({content_type}) with response: ({content})".format(
                    content_type=response_data.headers["content-type"],
                    content=response_data.content))

        return response_data 
