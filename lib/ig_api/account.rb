require 'ostruct'

module IgApi
  class Account
    def initialized
      @api = nil
      @settings = {}
    end

    def api
      @api = IgApi::Http.new if @api.nil?

      @api
    end

    def using(session)
      User.new session: session
    end

    # def login(username, password, config = IgApi::Configuration.new)
    #   user = User.new username: username,
    #                   password: password
    #
    #   request = api.post(
    #     Constants::URL + 'accounts/login/',
    #     format(
    #       'ig_sig_key_version=4&signed_body=%s',
    #       IgApi::Http.generate_signature(
    #         device_id: user.device_id,
    #         login_attempt_user: 0, password: user.password, username: user.username,
    #         _csrftoken: 'missing', _uuid: IgApi::Http.generate_uuid
    #       )
    #     )
    #   ).with(ua: user.useragent).exec
    #
    #
    #   response = JSON.parse request.body, object_class: OpenStruct
    #
    #   return response if response.error_type == 'checkpoint_challenge_required'
    #
    #   raise response.message if response.status == 'fail'
    #
    #   logged_in_user = response.logged_in_user
    #   user.data = logged_in_user
    #
    #   cookies_array = []
    #   all_cookies = request.get_fields('set-cookie') || []
    #   all_cookies.each do |cookie|
    #     cookies_array.push(cookie.split('; ')[0])
    #   end
    #   cookies = cookies_array.join('; ')
    #   user.config = config
    #   user.session = cookies
    #
    #   user
    # end

    def init
      # Initialize Login helpers

      # Restore cookies if they exist in settings
      if @settings["cookies"]
        @private[:cookies] = HTTP::CookieJar.new
        @settings["cookies"].each { |key, value| @private[:cookies].add(key, value) }
      end

      # Set instance variables from settings or defaults
      @authorization_data = @settings.fetch("authorization_data", {})
      @last_login = @settings["last_login"]
      set_timezone_offset(@settings.fetch("timezone_offset", @timezone_offset))
      set_device(@settings["device_settings"])

      # Set Bloks versioning ID (constant value)
      @bloks_versioning_id = "ce555e5500576acd8e84a66018f54a05720f2dce29f0bb5a1f97f0c10d6fac48"

      # Set additional instance variables
      set_user_agent(@settings["user_agent"])
      set_uuids(@settings.fetch("uuids", {}))
      #set_locale(@settings.fetch("locale", @locale))
      #set_country(@settings.fetch("country", @country))
      #set_country_code(@settings.fetch("country_code", @country_code))
      @mid = @settings.fetch("mid", cookie_dict["mid"])
      set_ig_u_rur(@settings["ig_u_rur"])
      set_ig_www_claim(@settings["ig_www_claim"])

      # Initialize headers
      headers = base_headers
      headers["Authorization"] = authorization
      @private[:headers].merge!(headers)

      true
    end


    def login(username: nil, password: nil, relogin: false, verification_code: "")
      # Login

      # Assign username and password if provided
      @username = username if username
      @password = password if password

      # Raise an error if username or password is missing
      raise BadCredentials, "Both username and password must be provided." if @username.nil? || @password.nil?

      # Handle relogin process
      if relogin
        @authorization_data = {}
        @private[:headers]&.delete("Authorization")
        @private[:cookies]&.clear
        raise ReloginAttemptExceeded if @relogin_attempt.to_i > 1

        @relogin_attempt = @relogin_attempt.to_i + 1
      end

      # Skip login if already logged in and not relogging
      return true if @user_id && !relogin

      # Pre-login flow to handle throttling
      begin
        #pre_login_flow
      rescue PleaseWaitFewMinutes, ClientThrottledError
        logger.warn("Ignore 429: Continue login")
      end

      # Encrypt password and prepare login data
      enc_password = password_encrypt(@password)
      data = {
        "jazoest" => generate_jazoest(@phone_id),
        "country_codes" => "[{\"country_code\":\"#{@country_code.to_i}\",\"source\":[\"default\"]}]",
        "phone_id" => @phone_id,
        "enc_password" => enc_password,
        "username" => @username,
        "adid" => @advertising_id,
        "guid" => @uuid,
        "device_id" => @android_device_id,
        "google_tokens" => "[]",
        "login_attempt_count" => "0"
      }

      begin
        # Attempt to log in
        logged = private_request("accounts/login/", data, login: true)
        @authorization_data = parse_authorization(
          last_response[:headers]["ig-set-authorization"]
        )
      rescue TwoFactorRequired => e
        # Handle two-factor authentication
        if verification_code.strip.empty?
          raise TwoFactorRequired, "#{e.message} (you did not provide verification_code for login method)"
        end

        two_factor_identifier = last_json.dig("two_factor_info", "two_factor_identifier")
        data = {
          "verification_code" => verification_code,
          "phone_id" => @phone_id,
          "_csrftoken" => @token,
          "two_factor_identifier" => two_factor_identifier,
          "username" => @username,
          "trust_this_device" => "0",
          "guid" => @uuid,
          "device_id" => @android_device_id,
          "waterfall_id" => SecureRandom.uuid,
          "verification_method" => "3"
        }

        logged = private_request("accounts/two_factor_login/", data, login: true)
        @authorization_data = parse_authorization(
          last_response[:headers]["ig-set-authorization"]
        )
      end

      if logged
        login_flow
        @last_login = Time.now.to_i
        true
      else
        false
      end
    end

    def login_flow
      # Emulate mobile app behavior after login

      check_flow = []
      check_flow << get_reels_tray_feed("cold_start")
      check_flow << get_timeline_feed("cold_start_fetch")

      check_flow.all?
    end

    def get_timeline_feed(reason: "pull_to_refresh", max_id: nil)
      # Get your timeline feed

      headers = {
        "X-Ads-Opt-Out" => "0",
        "X-DEVICE-ID" => @uuid,
        "X-CM-Bandwidth-KBPS" => "-1.000", # Simulated bandwidth value
        "X-CM-Latency" => rand(1..5).to_s
      }

      data = {
        "has_camera_permission" => "1",
        "feed_view_info" => "[]", # Placeholder for media view info
        "phone_id" => @phone_id,
        "reason" => reason,
        "battery_level" => 100,
        "timezone_offset" => @timezone_offset.to_s,
        "_csrftoken" => @token,
        "device_id" => @uuid,
        "request_id" => @request_id,
        "_uuid" => @uuid,
        "is_charging" => rand(0..1),
        "is_dark_mode" => 1,
        "will_sound_on" => rand(0..1),
        "session_id" => @client_session_id,
        "bloks_versioning_id" => @bloks_versioning_id
      }

      # Add pull-to-refresh data
      data["is_pull_to_refresh"] = ["pull_to_refresh", "auto_refresh"].include?(reason) ? "1" : "0"

      # Add pagination data
      data["max_id"] = max_id if max_id

      private_request("feed/timeline/", data.to_json, with_signature: false, headers: headers)
    end

    def get_reels_tray_feed(reason: "pull_to_refresh")
      # Get your reels tray feed

      data = {
        "supported_capabilities_new" => config::SUPPORTED_CAPABILITIES,
        "reason" => reason,
        "timezone_offset" => @timezone_offset.to_s,
        "tray_session_id" => @tray_session_id,
        "request_id" => @request_id,
        "page_size" => 50,
        "_uuid" => @uuid
      }

      # Add reel tray impressions based on the reason
      if reason == "cold_start"
        data["reel_tray_impressions"] = {}
      else
        data["reel_tray_impressions"] = { @user_id => Time.now.to_f.to_s }
      end

      private_request("feed/reels_tray/", data)
    end


    def generate_jazoest(symbols)
      amount = symbols.chars.sum { |s| s.ord }
      "2#{amount}"
    end


    def set_device(device: nil, reset: false)
      # Helper to set a device for login

      # Set default device settings if no device is provided
      @device_settings = device || {
        "app_version" => "269.0.0.18.75",
        "android_version" => 26,
        "android_release" => "8.0.0",
        "dpi" => "480dpi",
        "resolution" => "1080x1920",
        "manufacturer" => "OnePlus",
        "device" => "devitron",
        "model" => "6T Dev",
        "cpu" => "qcom",
        "version_code" => "314665256"
      }

      # Store the device settings in the settings hash
      #@settings ||= {}
      @settings["device_settings"] = @device_settings

      # If reset is true, reset UUIDs and optionally reset settings
      if reset
        set_uuids({})
        # Uncomment the line below if you want to reset the entire settings
        # @settings = get_settings
      end

      true
    end

    private

    def set_user_agent(user_agent: "", reset: false)
      # Helper to set user agent

      data = @device_settings.merge("locale" => @locale)
      @user_agent = user_agent.presence || format(config::USER_AGENT_BASE, **data)

      # Store the user agent in the settings
      @settings ||= {}
      @settings["user_agent"] = @user_agent

      # If reset is true, reset UUIDs and optionally reset settings
      if reset
        set_uuids({})
        # Uncomment the line below if you want to reset the entire settings
        # @settings = get_settings
      end

      true
    end

    def set_uuids(uuids = {})
      # Helper to set UUIDs

      @phone_id = uuids.fetch("phone_id", generate_uuid)
      @uuid = uuids.fetch("uuid", generate_uuid)
      @client_session_id = uuids.fetch("client_session_id", generate_uuid)
      @advertising_id = uuids.fetch("advertising_id", generate_uuid)
      @android_device_id = uuids.fetch("android_device_id", generate_android_device_id)
      @request_id = uuids.fetch("request_id", generate_uuid)
      @tray_session_id = uuids.fetch("tray_session_id", generate_uuid)
      # Uncomment this line if needed
      # @device_id = uuids.fetch("device_id", generate_uuid)

      @settings ||= {}
      @settings["uuids"] = uuids

      true
    end

    def generate_uuid(prefix: "", suffix: "")
      # Helper to generate UUIDs
      "#{prefix}#{SecureRandom.uuid}#{suffix}"
    end

    def self.search_for_user_graphql(user, username)
      endpoint = "https://www.instagram.com/#{username}/?__a=1"
      result = IgApi::API.http(url: endpoint, method: 'GET', user: user)

      response = JSON.parse result.body, symbolize_names: true, object_class: OpenStruct
      return nil unless response.user.any?
    end

    def search_for_user(user, username)
      rank_token = IgApi::Http.generate_rank_token user.session.scan(/ds_user_id=([\d]+);/)[0][0]
      endpoint = 'https://i.instagram.com/api/v1/users/search/'
      param = format('?is_typehead=true&q=%s&rank_token=%s', username, rank_token)
      result = api.get(endpoint + param)
                   .with(session: user.session, ua: user.useragent).exec

      result = JSON.parse result.body, object_class: OpenStruct

      if result.num_results > 0
        user_result = result.users[0]
        user_object = IgApi::User.new username: username
        user_object.data = user_result
        user_object.session = user.session
        user_object
      end
    end

    def list_direct_messages(user, limit = 100)
      base_url = 'https://i.instagram.com/api/v1'
      rank_token = IgApi::Http.generate_rank_token user.session.scan(/ds_user_id=([\d]+);/)[0][0]

      inbox_params = "?persistentBadging=true&use_unified_inbox=true&show_threads=true&limit=#{limit}"

      # each type of message requires a uniqe fetch
      inbox_endpoint = base_url + "/direct_v2/inbox/#{inbox_params}"
      inbox_pending_endpoint = base_url + "/direct_v2/pending_inbox/#{inbox_params}"

      param = format('&is_typehead=true&q=%s&rank_token=%s', user.username, rank_token)

      inbox_result = api.get(inbox_endpoint + param).with(session: user.session, ua: user.useragent).exec
      inbox_result = JSON.parse inbox_result.body, object_class: OpenStruct

      inbox_pending_result = api.get(inbox_pending_endpoint + param).with(session: user.session, ua: user.useragent).exec
      inbox_pending_result = JSON.parse inbox_pending_result.body, object_class: OpenStruct

      threads = ((inbox_result.inbox.threads || []) + (inbox_pending_result.inbox.threads || [])).flatten
      all_messages = []

      # fetch + combine past messages from parent thread
      threads.each do |thread|
        # thread_id = thread.thread_v2_id # => 17953972372244048 DO NOT USE V2!
        thread_id = thread.thread_id # => 340282366841710300949128223810596505168
        cursor_id = thread.oldest_cursor # '28623389310319272791051433794338816'

        thread_endpoint = base_url + "/direct_v2/threads/#{thread_id}/?cursor=#{cursor_id}"
        param = format('&is_typehead=true&q=%s&rank_token=%s', user.username, rank_token)

        result = api.get(thread_endpoint + param).with(session: user.session, ua: user.useragent).exec
        result = JSON.parse result.body, object_class: OpenStruct

        if result.thread && result.thread.items.count > 0
          older_messages = result.thread.items.sort_by(&:timestamp) # returns oldest --> newest

          all_messages << {
            thread_id: thread_id,
            recipient_username: thread.users.first.try(:username), # possible to have 1+ or none (e.g. 'mention')
            conversations: older_messages << thread.items.first
          }
        elsif result.thread && result.thread.last_permanent_item
          all_messages << {
            thread_id: thread_id,
            recipient_username: thread.users.first.try(:username),
            conversations: result.thread.last_permanent_item
          }
        end
      end

      all_messages
    end
  end
end
