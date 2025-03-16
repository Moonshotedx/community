# frozen_string_literal: true

module User::Omniauthable
  extend ActiveSupport::Concern

  TEMP_EMAIL_PREFIX = 'change@me'
  TEMP_EMAIL_REGEX  = /\A#{TEMP_EMAIL_PREFIX}/

  included do
    devise :omniauthable

    def omniauth_providers
      Devise.omniauth_configs.keys
    end

    def email_present?
      email && email !~ TEMP_EMAIL_REGEX
    end
  end

  class_methods do
    def find_for_omniauth(auth, signed_in_resource = nil)
      # EOLE-SSO Patch
      auth.uid = (auth.uid[0][:uid] || auth.uid[0][:user]) if auth.uid.is_a? Hashie::Array
      identity = Identity.find_for_omniauth(auth)

      # If a signed_in_resource is provided it always overrides the existing user
      # to prevent the identity being locked with accidentally created accounts.
      # Note that this may leave zombie accounts (with no associated identity) which
      # can be cleaned up at a later date.
      user   = signed_in_resource || identity.user
      user ||= reattach_for_auth(auth)
      user ||= create_for_auth(auth)

      if identity.user.nil?
        identity.user = user
        identity.save!
      end

      user
    end

    private

    def reattach_for_auth(auth)
      # If allowed, check if a user exists with the provided email address,
      # and return it if they does not have an associated identity with the
      # current authentication provider.

      # This can be used to provide a choice of alternative auth providers
      # or provide smooth gradual transition between multiple auth providers,
      # but this is discouraged because any insecure provider will put *all*
      # local users at risk, regardless of which provider they registered with.

      return unless ENV['ALLOW_UNSAFE_AUTH_PROVIDER_REATTACH'] == 'true'

      email, email_is_verified = email_from_auth(auth)
      return unless email_is_verified

      user = User.find_by(email: email)
      return if user.nil? || Identity.exists?(provider: auth.provider, user_id: user.id)

      user
    end

    def create_for_auth(auth)
      # Create a user for the given auth params. If no email was provided,
      # we assign a temporary email and ask the user to verify it on
      # the next step via Auth::SetupController.show

      email, email_is_verified = email_from_auth(auth)

      user = User.new(user_params_from_auth(email, auth))

      begin
        user.account.avatar_remote_url = auth.info.image if /\A#{URI::DEFAULT_PARSER.make_regexp(%w(http https))}\z/.match?(auth.info.image)
      rescue Mastodon::UnexpectedResponseError
        user.account.avatar_remote_url = nil
      end

      user.mark_email_as_confirmed! if email_is_verified
      user.save!
      user
    end

    def email_from_auth(auth)
      strategy          = Devise.omniauth_configs[auth.provider.to_sym].strategy
      assume_verified   = strategy&.security&.assume_email_is_verified
      email_is_verified = auth.info.verified || auth.info.verified_email || auth.info.email_verified || assume_verified
      email             = auth.info.verified_email || auth.info.email

      [email, email_is_verified]
    end

    def user_params_from_auth(email, auth)
      Rails.logger.info("Auth provider: #{auth.provider}")
      
      display_name_claim = nil
      display_name = nil
      
      # Get the provider config properly through Devise
      provider_config = Devise.omniauth_configs[auth.provider.to_sym]
      Rails.logger.info("Provider config: #{provider_config.inspect}")
      
      if provider_config.present?
        # For OpenID Connect, the display_name_claim is in the options
        if auth.provider == 'openid_connect' && provider_config.options.is_a?(Hash)
          display_name_claim = provider_config.options[:display_name_claim]
          Rails.logger.info("Display name claim from provider config: #{display_name_claim}")
        end
      end
      
      if display_name_claim.present?
        # Try to extract the claim value from different possible locations
        if auth.extra.respond_to?(:raw_info) && auth.extra.raw_info.present?
          if auth.extra.raw_info.respond_to?(display_name_claim)
            display_name = auth.extra.raw_info.send(display_name_claim)
            Rails.logger.info("Found display_name via method call on raw_info: #{display_name}")
          elsif auth.extra.raw_info.respond_to?(:[]) 
            display_name = auth.extra.raw_info[display_name_claim.to_s] || auth.extra.raw_info[display_name_claim.to_sym]
            Rails.logger.info("Found display_name via hash access on raw_info: #{display_name}")
          end
        end
        
        # If not found in raw_info, try info
        if display_name.blank? && auth.info.present?
          if auth.info.respond_to?(display_name_claim)
            display_name = auth.info.send(display_name_claim)
            Rails.logger.info("Found display_name via method call on info: #{display_name}")
          elsif auth.info.respond_to?(:[])
            display_name = auth.info[display_name_claim.to_s] || auth.info[display_name_claim.to_sym]
            Rails.logger.info("Found display_name via hash access on info: #{display_name}")
          end
        end
      end
      
      # If no display_name found yet, fall back to standard fields
      if display_name.blank?
        Rails.logger.info("Auth info full_name: #{auth.info.full_name.inspect}")
        Rails.logger.info("Auth info name: #{auth.info.name.inspect}")
        Rails.logger.info("Auth info first_name: #{auth.info.first_name.inspect}")
        Rails.logger.info("Auth info last_name: #{auth.info.last_name.inspect}")
        
        display_name = auth.info.full_name || auth.info.name || [auth.info.first_name, auth.info.last_name].join(' ')
      end
      
      Rails.logger.info("Final display_name: #{display_name.inspect}")

      {
        email: email || "#{TEMP_EMAIL_PREFIX}-#{auth.uid}-#{auth.provider}.com",
        agreement: true,
        external: true,
        account_attributes: {
          username: ensure_unique_username(ensure_valid_username(auth.uid)),
          display_name: display_name,
        },
      }
    end

    def ensure_unique_username(starting_username)
      username = starting_username
      i        = 0

      while Account.exists?(username: username, domain: nil)
        i       += 1
        username = "#{starting_username}_#{i}"
      end

      username
    end

    def ensure_valid_username(starting_username)
      starting_username = starting_username.split('@')[0]
      temp_username = starting_username.gsub(/[^a-z0-9_]+/i, '')
      temp_username.truncate(30, omission: '')
    end
  end
end
