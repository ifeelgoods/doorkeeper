module Doorkeeper
  module Request
    class AccountApplication < Strategy
      delegate :original_resource_owner, :client, to: :server

      def request
        @request ||= OAuth::AccountAccessTokenRequest.new(Doorkeeper.configuration, client, original_resource_owner)
      end

      def authorize
        request.authorize
      end
    end
  end
end
