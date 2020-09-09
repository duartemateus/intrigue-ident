###
### Please note - these methods may be used inside task modules, or inside libraries within
### Intrigue. An attempt has been made to make them abstract enough to use anywhere inside the
### application, but they are primarily designed as helpers for tasks. This is why you'll see
### references to @task_result in these methods. We do need to check to make sure it's available before
### writing to it.
###

# This module exists for common web functionality - inside a web browser
module Intrigue
module Ident
  module HttpBrowser

    def ident_create_browser_session

      # first check if we're allowed to create a session by the global config
      return nil unless Intrigue::Config::GlobalConfig.config["browser_enabled"]

      # start a new session
      args = ['headless', 'disable-gpu', 'disable-dev-shm-usage', 
       'ignore-certificate-errors', 'disable-popup-blocking', 'disable-translate']

      # configure the driver to run in headless mode
      options = Selenium::WebDriver::Chrome::Options.new(args: args)
      
      # create a driver
      driver = Selenium::WebDriver.for :chrome, { options: options }

      # set size 
      driver.manage.window.size = Selenium::WebDriver::Dimension.new(1280, 1024)

      # set a default timeout
      driver.manage.timeouts.implicit_wait = 20 # seconds
    
    driver 
    end

    def ident_destroy_browser_session(session)

      return false unless session

      # get the full group id (driver + browser)
      begin

        # HACK HACK HACK- get the chromedriver process before we quit
        #driver_pid = session.driver.browser.instance_variable_get(:@service).instance_variable_get(:@process).pid

        # attempt to quit gracefully...
        session.close

        #pgid = Process.getpgid(driver_pid)

        # violent delights have violent ends
        #Process.kill('KILL', -pgid )
        #Process.kill('KILL', driver_pid )
      rescue Selenium::WebDriver::Error::UnknownError => e
        _log_error "Error trying to kill our browser session #{e}"
      rescue Errno::ESRCH => e
          # already dead
        _log_error "Error trying to kill our browser session #{e}"
      rescue Net::ReadTimeout => e
        _log_error "Timed out trying to close our session.. #{e}"
      end

    true 
    end

    def ident_safe_browser_action
      begin

        results = yield

      rescue Errno::EMFILE => e
        _log_error "Too many open files: #{e}" if @task_result
      rescue Addressable::URI::InvalidURIError => e
        _log_error "Invalid URI: #{e}" if @task_result
      rescue Net::ReadTimeout => e
        _log_error "Timed out, moving on" if @task_result
      rescue Selenium::WebDriver::Error::WebDriverError => e
        # skip simple errors where we're testing JS libs
        unless ("#{e}" =~ /is not defined/ || "#{e}" =~ /Cannot read property/)
          _log_error "Webdriver issue #{e}" if @task_result
        end
      rescue Selenium::WebDriver::Error::NoSuchWindowError => e
        _log_error "Lost our window #{e}" if @task_result
      rescue Selenium::WebDriver::Error::UnknownError => e
        # skip simple errors where we're testing JS libs
        unless ("#{e}" =~ /is not defined/ || "#{e}" =~ /Cannot read property/)
          _log_error "#{e}" if @task_result
        end
      rescue Selenium::WebDriver::Error::UnhandledAlertError => e
        _log_error "Unhandled alert open: #{e}" if @task_result
      rescue Selenium::WebDriver::Error::NoSuchElementError
        _log_error "No such element #{e}, moving on" if @task_result
      rescue Selenium::WebDriver::Error::StaleElementReferenceError
        _log_error "No such element ref #{e}, moving on" if @task_result
      end
    results
    end

    def ident_capture_document(session, uri)
      return nil unless session # always make sure the session is real

      # browse to our target
      safe_browser_action do
        # visit the page
        session.navigate.to(uri)
        # Capture Title
        page_title = session.title
        # Capture Body Text
        page_contents = session.page_source
        # Capture DOM
        rendered_page = session.execute_script("return document.documentElement.innerHTML")

        # return our hash
        return { :title => page_title, :contents => page_contents, :rendered => rendered_page }
      end
    nil 
    end

    def ident_capture_screenshot(session, uri)
      return nil unless session # always make sure the session is real

      # browse to our target
      safe_browser_action do
        session.navigate.to(uri)
      end

      #
      # Capture a screenshot
      #
      base64_image_contents = nil
      safe_browser_action do
        tempfile = Tempfile.new(['screenshot', '.png'])
        session.save_screenshot(tempfile.path)
        _log "Saved Screenshot to #{tempfile.path}"
        # open and read the file's contents, and base64 encode them
        base64_image_contents = Base64.encode64(File.read(tempfile.path))
        # cleanup
        tempfile.close
        tempfile.unlink
      end

    base64_image_contents
    end

    def ident_gather_javascript_libraries(session, uri)
      return nil unless session # always make sure the session is real
      
      safe_browser_action do
        session.navigate.to(uri)
      end

      libraries = []

      checks = [
        { library: "Angular", script: 'angular.version.full' },
        # Backbone
        # Test site: https://app.casefriend.com/
        # Examples: https://github.com/jashkenas/backbone/wiki/projects-and-companies-using-backbone
        { library: "Backbone", script: 'Backbone.VERSION' },
        # D3
        # Test site: https://d3js.org/
        # Examples: https://kartoweb.itc.nl/kobben/D3tests/index.html
        { library: "D3", script: 'd3.version' },
        # Dojo
        # Test site: http://demos.dojotoolkit.org/demos/mobileCharting/demo.html
        # Examples: http://demos.dojotoolkit.org/demos/
        { library: "Dojo", script: 'dojo.version' },
        # Ember
        # Test site: https://secure.ally.com/
        # Examples: http://builtwithember.io/
        { library: "Ember", script: 'Ember.VERSION' },

        # Honeybadger
        { library: "Honeybadger", script: 'Honeybadger.getVersion()' },

        # Intercom
        # Examples: https://bugcrowd.com
        { library: "Intercom", script: 'Intercom("version")' },

        # Jquery
        # Test site: http://www.eddiebauer.com/
        # Test site: https://www.underarmour.com
        { library: "jQuery", script: 'jQuery.fn.jquery' },
        # Jquery tools
        # Test site: http://www.eddiebauer.com/
        { library: "jQuery Tools", script: 'jQuery.tools.version' },
        # Jquery UI
        # Test site: http://www.eddiebauer.com/
        # Test site: https://www.underarmour.com
        { library: "jQuery UI", script: 'jQuery.ui.version' },

        # Test site:
        # Examples: http://knockoutjs.com/examples/
        #version = session.evaluate_script('knockout.version')
        # { :product => "Knockout", check: 'knockout.version' }

        # Modernizr
        { library: "Modernizr", script: 'Modernizr._version' },

        # Paper.js
        # Test site: http://paperjs.org/examples/boolean-operations
        # Examples: http://paperjs.org/examples

        # Prototype
        # Test site:
        # Examples:
        # version = session.evaluate_script('Prototype.version')
        # { product: "Prototype", check: 'Prototype.version' },

        { library: "Paper", script: 'paper.version' },

        # React
        # Test site: https://weather.com/
        # Examples: https://react.rocks/
        { library: "React", script: 'React.version' },

        # RequireJS
        # Test site: https://www.homedepot.com
        { library: "RequireJS", script: 'requirejs.version' },

        # Underscore
        # Test site: https://app.casefriend.com/#sessions/login
        # Test site: https://store.dji.com/
        { library: "Underscore", script: '_.VERSION' },

        # YUI
        # Test site: https://yuilibrary.com/yui/docs/event/basic-example.html
        # Examples: https://yuilibrary.com/yui/docs/examples/
        { library: "YUI", script: 'YUI().version' }
      ]

      checks.each do |check|

        hacky_javascript = "return #{check[:script]};"

        # run our script in a browser
        version = safe_browser_action do
          session.execute_script(hacky_javascript)
        end

        if version
          _log_good "Detected #{check[:library]} #{version}" if @task_result
          libraries << {"library" => "#{check[:library]}", "version" => "#{version}" }
        end

      end

    libraries
    end


  end
end
end
