module Doorkeeper::OAuth
  class AccountAccessTokenRequest
    include Doorkeeper::Validations
    include Doorkeeper::OAuth::Helpers

    validate :client,         :error => :invalid_client
    validate :original_resource_owner, :error => :invalid_original_resource_owner

    attr_accessor :server, :original_resource_owner, :client

    def initialize(server, client, original_resource_owner)
      @server          = server
      @original_resource_owner  = original_resource_owner
      @client          = client
    end

    def authorize
      validate
      @response = if valid?
        find_or_create_access_token
        TokenResponse.new access_token
      else
        ErrorResponse.from_request self
      end
    end

    def valid?
      self.error.nil?
    end

    def access_token
      return unless client.present? && original_resource_owner.present?
      @access_token ||= Doorkeeper::AccessToken.matching_token_for client, original_resource_owner.id, nil
    end

  private

    def find_or_create_access_token
      if access_token
        access_token.expired? ? revoke_and_create_access_token : access_token
      else
        create_access_token
      end
    end

    def revoke_and_create_access_token
      access_token.revoke
      create_access_token
    end

    def create_access_token
      @access_token = Doorkeeper::AccessToken.create!({
        :application_id     => client.id,
        :resource_owner_id  => original_resource_owner.id,
        :scopes             => '',
        :expires_in         => server.access_token_expires_in,
        :use_refresh_token  => server.refresh_token_enabled?
      })
    end

    def validate_client
      !!client
    end

    def validate_original_resource_owner
      !!original_resource_owner
    end
  end
end
