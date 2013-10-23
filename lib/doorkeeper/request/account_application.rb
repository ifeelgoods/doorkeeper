module Doorkeeper
  module Request
    class AccountApplication
      def self.build(server)
        new(server.client, server.original_resource_owner, server)
      end

      attr_accessor :client, :original_resource_owner, :server

      def initialize(client, original_resource_owner, server)
        @client, @original_resource_owner, @server = client, original_resource_owner, server
      end

      def request
        @request ||= OAuth::AccountAccessTokenRequest.new(Doorkeeper.configuration, client, original_resource_owner)
      end

      def authorize
        request.authorize
      end
    end
  end
end
