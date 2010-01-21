require 'openid/extensions/oauth'
require 'openid/message'
require 'openid/server'
require 'openid/consumer/responses'

require 'testutil'
require 'mocha'

module OpenID
  module OAuthTest
    class OAuthRequestTestCase < Test::Unit::TestCase
      def setup
        @req = OAuthHybrid::Request.new
      end

      def test_construct
        assert_equal(nil, @req.consumer_key)
        assert_equal(nil, @req.scope)
        assert_equal('oauth', @req.ns_alias)
        
        req2 = OAuthHybrid::Request.new("my_consumer_key", "my_scope")
        assert_equal("my_consumer_key", req2.consumer_key)
        assert_equal("my_scope", req2.scope)
      end

      def test_get_extension_args
        assert_equal({'consumer_key' => nil, 'scope' => nil}, @req.get_extension_args)
        @req.scope = "my_scope"
        assert_equal({'consumer_key' => nil, 'scope' => 'my_scope'}, @req.get_extension_args)
        @req.consumer_key = "my_consumer_key"
        assert_equal({'consumer_key' => 'my_consumer_key', 'scope' => 'my_scope'}, @req.get_extension_args)
      end

      def test_parse_extension_args
        args = {'consumer_key' => 'my_consumer_key',
                'scope' => 'my_scope'}
        @req.parse_extension_args(args)
        assert_equal('my_consumer_key', @req.consumer_key)
        assert_equal('my_scope', @req.scope)
      end

      def test_parse_extension_args_empty
        @req.parse_extension_args({})
        assert_equal(nil, @req.consumer_key)
        assert_equal(nil, @req.scope)
      end

      def test_from_openid_request
        openid_req_msg = Message.from_openid_args({
          'mode' => 'checkid_setup',
          'ns' => OPENID2_NS,
          'ns.oauth' => OAuthHybrid::NS_URI,
          'oauth.consumer_key' => 'oauth_consumer_key',
          'oauth.scope' => 'for_testing_only'
          })
        oid_req = Server::OpenIDRequest.new
        oid_req.message = openid_req_msg
        req = OAuthHybrid::Request.from_openid_request(oid_req)
        assert_equal('oauth_consumer_key', req.consumer_key)
        assert_equal('for_testing_only', req.scope)
      end

      def test_from_openid_request_no_oauth
        message = Message.new
        openid_req = Server::OpenIDRequest.new
        openid_req.message = message
        oauth_req = OAuthHybrid::Request.from_openid_request(openid_req)
        assert(oauth_req.nil?)
      end
    end

    class DummySuccessResponse
      attr_accessor :message

      def initialize(message, signed_stuff)
        @message = message
        @signed_stuff = signed_stuff
      end

      def get_signed_ns(ns_uri)
        return @signed_stuff
      end

    end

    class OAuthResponseTestCase < Test::Unit::TestCase      
      def setup
        @req = OAuthHybrid::Response.new

        @oauth_consumer = mock()
        @oauth_consumer.stubs(:key => "key", :secret => "secret")
        @request_token = mock()
        @oauth_consumer.stubs(:token => "my_key", :secret => "my_secret", :consumer => @oauth_consumer)
      end

      def test_construct
        assert_equal(nil, @req.request_token)
        assert_equal(nil, @req.scope)
        assert_equal('oauth', @req.ns_alias)

        req2 = OAuthHybrid::Response.new(@request_token, 'my_verifier', 'my_scope')
        assert_equal(@request_token, req2.request_token)
        assert_equal('my_verifier', req2.verifier)
        assert_equal('my_scope', req2.scope)
      end

      def test_get_extension_args
        assert_equal({'verifier'=>nil, 'request_token' => nil, 'scope' => nil}, @req.get_extension_args)
        @req.request_token = @request_token
        assert_equal({'verifier'=> nil, 'request_token' => @request_token, 'scope' => nil}, @req.get_extension_args)
        @req.scope = 'my_scope'
        assert_equal({'verifier'=> nil, 'request_token' => @request_token, 'scope' => 'my_scope'}, @req.get_extension_args)
        @req.verifier = 'my_verifier'
        assert_equal({'verifier'=> 'my_verifier', 'request_token' => @request_token, 'scope' => 'my_scope'}, @req.get_extension_args)
      end

      def test_parse_extension_args
        args = {'request_token' => @request_token,
                'scope' => 'my_scope'}
        @req.parse_extension_args(args)
        assert_equal(@request_token, @req.request_token)
        assert_equal('my_scope', @req.scope)
      end

      def test_parse_extension_args_empty
        @req.parse_extension_args({})
        assert_equal(nil, @req.request_token)
        assert_equal(nil, @req.scope)
      end

      def test_from_success_response        
        openid_req_msg = Message.from_openid_args({
          'mode' => 'id_res',
          'ns' => OPENID2_NS,
          'ns.oauth' => OAuthHybrid::NS_URI,
          'oauth.request_token' => @request_token,
          'oauth.scope' => 'for_testng_only'
          })
        signed_stuff = {
          'request_token' => @request_token,
          'scope' => 'for_testing_only'
        }
        oid_req = DummySuccessResponse.new(openid_req_msg, signed_stuff)
        req = OAuthHybrid::Response.from_success_response(oid_req)
        assert_equal(@request_token, req.request_token)
        assert_equal('for_testing_only', req.scope)
      end

      def test_from_success_response_unsigned
        openid_req_msg = Message.from_openid_args({
          'mode' => 'id_res',
          'ns' => OPENID2_NS,
          'ns.oauth' => OAuthHybrid::NS_URI,
          'oauth.request_token' => @request_token,
          'oauth.scope' => 'for_testng_only'
          })
        signed_stuff = {}
        endpoint = OpenIDServiceEndpoint.new
        oid_req = Consumer::SuccessResponse.new(endpoint, openid_req_msg, signed_stuff)
        req = OAuthHybrid::Response.from_success_response(oid_req)
        assert(req.nil?, req.inspect)
      end
    end
  end
end
