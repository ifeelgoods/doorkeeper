require 'spec_helper_integration'

describe 'Account Application Request' do
  let(:client) { FactoryGirl.create :application }

  before do
    config_is_set(:grant_flows, ['account_application'])
    config_is_set(:original_resource_owner) do
      User.first
    end
  end

  context 'a valid request' do
    before do
      create_resource_owner
    end
    it 'authorizes the client and returns the token response' do
      params  = { grant_type: 'account_application', client_id: client.uid, client_secret: client.secret }

      post '/oauth/token', params

      should_have_json 'access_token', Doorkeeper::AccessToken.first.token
      should_have_json_within 'expires_in', Doorkeeper.configuration.access_token_expires_in, 1
      should_not_have_json 'scope'
      should_not_have_json 'refresh_token'

      should_not_have_json 'error'
      should_not_have_json 'error_description'
    end
  end

  context 'an invalid request' do
    context 'with a valid resource owner but not valid secret' do
      before do
        create_resource_owner
      end
      it 'does not authorize the client and returns the error' do
        params  = { grant_type: 'account_application', client_id: client.uid, client_secret: 'FAILS' }

        post '/oauth/token', params, headers

        should_have_json 'error', 'invalid_client'
        should_have_json 'error_description', translated_error_message(:invalid_client)
        should_not_have_json 'access_token'

        expect(response.status).to eq(401)
      end
    end

    context 'without a valid resource owner but valid secret' do
      it 'does not authorize the client and returns the error' do
        params  = { grant_type: 'account_application', client_id: client.uid, client_secret: client.secret }

        post '/oauth/token', params, headers

        should_have_json 'error', 'invalid_original_resource_owner'
        should_not_have_json 'access_token'

        expect(response.status).to eq(401)
      end
    end
  end
end
