module Doorkeeper
  class TokenInfoController < ::Doorkeeper::ApplicationController
    before_filter :validate_cors, :only => [:destroy, :options]

    def show
      if doorkeeper_token && doorkeeper_token.accessible?
        render :json => doorkeeper_token, :status => :ok
      else
        error = OAuth::ErrorResponse.new(:name => :invalid_request)
        render :json => error.body, :status => error.status
      end
    end

    # http://tools.ietf.org/html/draft-ietf-oauth-revocation-09
    def destroy
      # The authorization server first validates the client credentials
      if doorkeeper_token && doorkeeper_token.accessible?
        #  token_type_hint  OPTIONAL.  A hint about the type of the token
        # submitted for revocation.  Clients MAY pass this parameter in
        # order to help the authorization server to optimize the token
        # lookup.
        if params['token']
          if params['token_type_hint'] == 'refresh_token'
            revoke_refresh_token(params['token']) || revoke_access_token(params['token'])
          elsif params['token_type_hint'] == 'access_token'
            revoke_access_token(params['token']) || revoke_refresh_token(params['token'])
          else

          # If the server is unable to locate the token using
          # the given hint, it MUST extend its search accross all of its
          # supported token types.
            revoke_access_token(params['token']) || revoke_refresh_token(params['token'])
          end
        end

        # The authorization server responds with HTTP status code 200 if the
        # token has been revoked sucessfully or if the client submitted an  invalid token
          result = logout_url ? {:logout_url => logout_url} : {}
          render :json => result, :status => 200
          return
      else
        # If this
        # validation fails, the request is refused and the client is informed
        # of the error by the authorization server as described below.
        error = OAuth::ErrorResponse.new(:name => :invalid_request)
        render :json => error.body, :status => error.status
      end
    end

    def options
      render :nothing => true
    end

    private

    def revoke_refresh_token(token)
      tokens = Doorkeeper::AccessToken.where(:refresh_token => token)
      if tokens.size > 0
        tokens.each do |tok|
          return false unless same_owner?(doorkeeper_token,tok)
          tok.revoke
        end
        true
      else
        false
      end
    end

    def revoke_access_token(token)
      token = Doorkeeper::AccessToken.authenticate(token)
      return false unless same_owner?(doorkeeper_token,token)
      if token
        token.revoke
        true
      else
        false
      end
    end

    def same_owner?(token1,token2)
      return false unless token1.application_id == token2.application_id
      return true if token1.resource_owner_id == token2.resource_owner_id
    end

    def logout_url
      if params[:logout_url] && params[:logout_url] == 'true' && Doorkeeper.configuration.logout_url
        instance_eval &Doorkeeper.configuration.logout_url
      else
        nil
      end
    end

    def validate_cors
      if Doorkeeper.configuration.cors_options
        instance_eval &Doorkeeper.configuration.cors_options
      else
        nil
      end
    end

  end
end
