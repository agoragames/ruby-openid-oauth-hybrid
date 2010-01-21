# An implementation of the OpenID OAuth
# Extension Draft
# see: http://step2.googlecode.com/svn/spec/openid_oauth_extension/latest/openid_oauth_extension.html

require 'oauth'
require 'openid/extension'

module OpenID

  module OAuthHybrid
    NS_URI = "http://specs.openid.net/extensions/oauth/1.0"

    # An OAuth request, sent from a relying
    # party to a provider
    class Request < Extension
      attr_accessor :ns_alias, :ns_uri, :consumer_key, :scope
      def initialize(consumer_key=nil, scope=nil)
        @ns_alias = 'oauth'
        @ns_uri = NS_URI
        @consumer_key = consumer_key
        @scope = scope
      end

      # Instantiate a Request object from the arguments in a
      # checkid_* OpenID message
      # return nil if the extension was not requested.
      def self.from_openid_request(oid_req)
        oauth_req = new
        args = oid_req.message.get_args(NS_URI)
        if args == {}
          return nil
        end
        oauth_req.parse_extension_args(args)
        return oauth_req
      end

      # Set the state of this request to be that expressed in these
      # OAuth arguments
      def parse_extension_args(args)
        @consumer_key = args['consumer_key']
        @scope = args['scope']
      end

      def get_extension_args
        ns_args = {}
        ns_args['consumer_key'] = @consumer_key
        ns_args['scope'] = @scope
        return ns_args
      end
    end

    # A Provider Authentication Policy response, sent from a provider
    # to a relying party
    class Response < Extension
      attr_accessor :ns_alias, :ns_uri, :request_token, :verifier, :scope
      def initialize(request_token=nil, verifier=nil, scope=nil)
        @ns_alias = 'oauth'
        @ns_uri = NS_URI
        @request_token = request_token
        @verifier = verifier
        @scope = scope
      end

      # Create a Response object from an OpenID::Consumer::SuccessResponse
      def self.from_success_response(success_response)
        args = success_response.get_signed_ns(NS_URI)
        return nil if args.nil?
        oauth_resp = new
        oauth_resp.parse_extension_args(args)
        return oauth_resp
      end

      # parse the oauth arguments into the
      # internal state of this object
      def parse_extension_args(args)
        @request_token = args['request_token']
        @verifier = args['verifier']
        @scope = args['scope']
      end

      def get_extension_args
        ns_args = {}
        ns_args['request_token'] = @request_token
        ns_args['verifier'] = @verifier
        ns_args['scope'] = @scope
        return ns_args
      end
    end

    class Consumer
      
      def initialize(key = "", secret = nil, options = {})

        config = APP_CONFIG['openid']['oauth_hybrid']['consumer']
        
        key = config['consumer_key'] if key.blank? && config && config['consumer_key']
        secret = config['consumer_secret'] if secret.blank? && config && config['consumer_secret']
        if options.empty? && config
          options = {
            :site               => config['site'],
            :scheme             => :header,
            :http_method        => :post,
            :request_token_path => config['request_token_url'],
            :access_token_path  => config['access_token_url'],
            :authorize_path     => config['authorize_url']
          }
        end
        @consumer ||= OAuth::Consumer.new(key, secret, options)
      end

      def exchange_request_token(token = "", oauth_verifier = nil)
        request_token = OAuth::RequestToken.new @consumer, token
        options={}
        options[:oauth_verifier]=oauth_verifier if oauth_verifier
        access_token = request_token.get_access_token(options)
        access_token
      end
    end
  end
end