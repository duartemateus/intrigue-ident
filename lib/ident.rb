#!/usr/bin/env ruby

require 'net/http'
require 'openssl'
require 'zlib'

# load in generic utils
require_relative 'utils'
require_relative 'version'

# Load in http matchers and checks
###################################
require_relative 'http/matchers'
include Intrigue::Ident::Http::Matchers

require_relative 'http/check_factory'
require_relative '../checks/http/base'

# http fingerprints
check_folder = File.expand_path('../checks/http', File.dirname(__FILE__)) # get absolute directory
Dir["#{check_folder}/*.rb"].each { |file| require_relative file }

# http content checks (always run)
content_check_folder = File.expand_path('../checks/http/content', File.dirname(__FILE__)) # get absolute directory
Dir["#{content_check_folder}/*.rb"].each { |file| require_relative file }

# http content, wordpress specific checks
content_check_folder = File.expand_path('../checks/http/wordpress', File.dirname(__FILE__)) # get absolute directory
Dir["#{content_check_folder}/*.rb"].each { |file| require_relative file }

# General helpers (apply widely across protocols)

require_relative 'simple_socket'
require_relative 'banner_helpers'

# Load in ftp matchers and checks
#################################
require_relative 'ftp/matchers'
include Intrigue::Ident::Ftp::Matchers

require_relative 'ftp/check_factory'
require_relative '../checks/ftp/base'

# ftp fingerprints
check_folder = File.expand_path('../checks/ftp', File.dirname(__FILE__)) # get absolute directory
Dir["#{check_folder}/*.rb"].each { |file| require_relative file }

# Load in smtp matchers and checks
##################################
require_relative 'smtp/matchers'
include Intrigue::Ident::Smtp::Matchers

require_relative 'smtp/check_factory'
require_relative '../checks/smtp/base'

# smtp fingerprints
check_folder = File.expand_path('../checks/smtp', File.dirname(__FILE__)) # get absolute directory
Dir["#{check_folder}/*.rb"].each { |file| require_relative file }

# Load in snmp matchers and checks
##################################
require_relative 'snmp/matchers'
include Intrigue::Ident::Snmp::Matchers

require_relative 'snmp/check_factory'
require_relative '../checks/snmp/base'

# snmp fingerprints
check_folder = File.expand_path('../checks/snmp', File.dirname(__FILE__)) # get absolute directory
Dir["#{check_folder}/*.rb"].each { |file| require_relative file }

# Load vulndb client 
require_relative "vulndb_client"

# set default encoding
Encoding.default_external = Encoding::UTF_8
Encoding.default_internal = Encoding::UTF_8


# set a base directory so we can use in checks 
$ident_dir = File.expand_path('../', File.dirname(__FILE__))

module Intrigue
  module Ident

    def generate_smtp_request_and_check(ip, port=25, debug=false)

      # do the request (store as string and funky format bc of usage in core.. and  json conversions)
      banner_string = grab_banner_smtp(ip,port)
      details = {
        "details" => {
          "banner" => banner_string
        }
      }

      results = []

      # generate the checks 
      checks = Intrigue::Ident::Smtp::CheckFactory.checks.map{ |x| x.new.generate_checks }.compact.flatten

      # and run them against our result
      checks.each do |check|
        results << match_smtp_response_hash(check,details)
      end

    results.map{|x| (x || {}).merge({"banner" => banner_string})}.uniq.compact
    end


    def generate_ftp_request_and_check(ip, port=21, debug=false)

      # do the request (store as string and funky format bc of usage in core.. and  json conversions)
      banner_string = grab_banner_ftp(ip,port)
      details = {
        "details" => {
          "banner" => banner_string
        }
      }

      results = []

      # generate the checks 
      checks = Intrigue::Ident::Ftp::CheckFactory.checks.map{ |x| x.new.generate_checks }.compact.flatten

      # and run them against our result
      checks.each do |check|
        results << match_smtp_response_hash(check,details)
      end

    results.map{|x| (x || {}).merge({"banner" => banner_string})}.uniq.compact
    end

    def generate_snmp_request_and_check(ip, port=161, debug=false)
      
      # do the request (store as string and funky format bc of usage in core.. and  json conversions)
      banner_string = grab_banner_smtp(ip,port)
      details = {
        "details" => {
          "banner" => banner_string
        }
      }

      results = []

      # generate the checks 
      checks = Intrigue::Ident::Snmp::CheckFactory.checks.map{ |x| x.new.generate_checks }.compact.flatten

      # and run them against our result
      checks.each do |check|
        results << match_snmp_response_hash(check,details)
      end

    results.map{|x| (x || {}).merge({"banner" => banner_string})}.uniq.compact
    end

    # Used by intrigue-core... note that this will currently fail unless
    def generate_http_requests_and_check(url, opts={})

      dom_checks = opts[:enable_browser] || false
      debug = opts[:debug] || false
      only_base = opts[:'only-check-base-url']

      # gather all fingeprints for each product
      # this will look like an array of checks, each with a uri and a set of checks
      initial_checks = Intrigue::Ident::Http::CheckFactory.generate_initial_checks("#{url}")

      ##### 
      ##### Sanity check!
      #####
      failing_checks = initial_checks.select{|x| x if !x[:paths] }
      if failing_checks.compact.count > 0
        puts "FATAL! Unable to continue, the following checks are invalid, missing a path!"
        puts failing_checks.inspect
        return
      end

      ###
      ### Initial Checks
      ###

      # In order to ensure we check all urls associated with a check, we need to
      # group them up by each path, which is annoying because they're stored in
      # an array on each check. This line handles that. (take all the checks []
      # with each of their paths [], flatten and group by them
      initial_checks_by_path = initial_checks.map{|c| c[:paths].map{ |p|
        c.merge({:unique_path => p})} }.flatten

      # now we have them organized by a single path, group them up so we only
      # have to make a single request per unique path 
      grouped_initial_checks = initial_checks_by_path.group_by{|x| x[:unique_path] }

      # allow us to only select the base path (speeds things up)
      if only_base
        grouped_initial_checks = grouped_initial_checks.select{|x,y| x == url}
      end

      # Run'm!!!
      initial_results = _run_grouped_http_checks url, grouped_initial_checks, dom_checks, debug
    
      ###
      ### Follow-on Checks
      ### 
    
      ### Okay so, now we have a set of detected products, let's figure out our follown checks
      followon_checks = []
      detected_products = initial_results["fingerprint"].map{|x| x["product"] }.uniq
      detected_products.each do |prod|
        followon_checks.concat(Intrigue::Ident::Http::CheckFactory.generate_checks_for_product("#{url}", prod))
        #puts "Getting checks for product: #{prod} ... #{followon_checks.count}" if debug
      end
      
      # group them up by path (there can be multiple paths)
      followon_checks_by_path = followon_checks.map{|c| c[:paths].map{ |p|
        c.merge({:unique_path => p})} }.flatten

      # group'm as needed to run the checks
      grouped_followon_checks = followon_checks_by_path.group_by{|x| x[:unique_path] }
      
      # allow us to only select the base path (speeds things up)
      if only_base
        grouped_followon_checks = grouped_followon_checks.select{|x,y| x == url}
      end

      ### OKAY NOW WE HAVE a set of output that we can run product-specific checks on, run'm
      if grouped_followon_checks
        followon_results = _run_grouped_http_checks(url, grouped_followon_checks, dom_checks, debug)
      else
        followon_results = {
          "fingerprint" => [], 
          "content" => [],
          "responses" => [],
          "check_count" => []
        }
      end
      
      ###
      ### Generate output
      ###

      out = {
        "url" => initial_results["url"], # same
        "fingerprint" => initial_results["fingerprint"].concat(followon_results["fingerprint"]),
        "content" => initial_results["content"].concat(followon_results["content"]),
        "responses" => initial_results["responses"].concat(followon_results["responses"]),
        "initial_checks" => initial_results["check_count"],
        "followon_checks" => followon_results["check_count"]
      }

    out 
    end


    private

    def _run_grouped_http_checks(url, grouped_generated_checks, dom_checks, debug)

      # shove results into an array
      results = []

      # keep an array of the request / response details
      responses = []

      # keep track of timeouts
      timeout_count = 0

      # call the check on each uri
      grouped_generated_checks.each do |ggc|

        target_url = ggc.first

        if timeout_count > 2
          puts "Skipping #{target_url}, too many timeouts" if debug
          next 
        end

        # get the response using a normal http request
        # TODO - collect redirects here
        puts "Getting #{target_url}" if debug
        response_hash = ident_http_request :get, "#{target_url}"
      
        if response_hash[:timeout]
          puts "ERROR timed out on #{target_url}" if debug
          timeout_count += 1
        end 

        responses << response_hash

        # Only if we are running browser checks
        if dom_checks
          # get the dom via a browser
          if ggc.last.map{|c| c[:match_type] }.include?(:content_dom)
            #puts "We have a check for #{target_url} that requires the DOM, firing a browser"
            session = ident_create_browser_session
            browser_response = ident_capture_document(session,"#{target_url}")

            # save the response to our list of responses
            # TODO - collect redirects here
            # https://michaeltroutt.com/using-headless-chrome-to-find-link-redirects/
            responses << browser_response

            ident_destroy_browser_session session
          end
        end

        # Go ahead and match it up if we got a response!
        if response_hash || browser_response
          # call each check, collecting the product if it's a match
          ggc.last.each do |check|

            # if we have a check that should match the dom, run it
            if (check[:match_type] == :content_dom)
              results << match_browser_response_hash(check,browser_response) if dom_checks
            else #otherwise use the normal flow
              results << match_http_response_hash(check,response_hash)
            end

          end
        end
      end

      return nil unless results

      # Return all matches, minus the nils (non-matches), and grouped by check type
      out = results.compact.group_by{|x| x["type"] }

      # make sure we have an empty fingerprints array if we didnt' have any Matches
      out["check_count"] = grouped_generated_checks.map{|x| {"url" => x.first, "count" => x.last.count } }
      out["fingerprint"] = [] unless out["fingerprint"]
      out["content"] = [] unless out["content"]

      # only return unique results
      out["fingerprint"] = out["fingerprint"].uniq
      out["content"] = out["content"].uniq
      out["url"] = url

      # attach the responses
      out["responses"] = responses
      
    out
    end


    def _construct_match_response(check, data)

      if check[:type] == "fingerprint"
        calculated_version = (check[:dynamic_version].call(data) if check[:dynamic_version]) || check[:version] || ""
        calculated_update = (check[:dynamic_update].call(data) if check[:dynamic_update]) || check[:update] || ""

        calculated_type = "a" if check[:category] == "application"
        calculated_type = "h" if check[:category] == "hardware"
        calculated_type = "o" if check[:category] == "operating_system"
        calculated_type = "s" if check[:category] == "service" # literally made up

        vendor_string = check[:vendor].gsub(" ","_") if check[:vendor]
        product_string = check[:product].gsub(" ","_") if check[:product]

        version = "#{calculated_version}".gsub(" ","_")
        update = "#{calculated_update}".gsub(" ","_")

        cpe_string = "cpe:2.3:#{calculated_type}:#{vendor_string}:#{product_string}:#{version}:#{update}".downcase

        ##
        ## Support for Dynamic 
        ##
        if check[:dynamic_issue]
          issue = check[:dynamic_issue].call(data)
        elsif check[:issue]
          issue = check[:issue]
        else
          issue = nil
        end
        
        ##
        ## Support for Dynamic Hide
        ##
        if check[:dynamic_hide]
          hide = check[:dynamic_hide].call(data)
        elsif check[:hide]
          hide = check[:hide]
        else
          hide = false
        end

        ##
        ## Support for Dynamic Task
        ##
        if check[:dynamic_task]
          task = check[:dynamic_task].call(data)
        elsif check[:task]
          task = check[:task]
        else
          task = nil
        end

        to_return = {
          "type" => check[:type],
          "vendor" => check[:vendor],
          "product" => check[:product],
          "version" => calculated_version,
          "update" => calculated_update,
          "tags" => check[:tags],
          "match_type" => check[:match_type],
          "match_details" => check[:match_details],
          "hide" => hide,
          "cpe" => cpe_string,
          "issue" => issue, 
          "task" => task, # [{ :task_name => "example", :task_options => {}}]
          "inference" => check[:inference]
        }

      elsif check[:type] == "content"

        # Mandatory lambda
        result = check[:dynamic_result].call(data)

        ##
        ## Support for Dynamic Issue (must be dynamic, these checks always run)
        ##
        if result
        
          if check[:dynamic_hide]
            hide = check[:dynamic_hide].call(data) 
          else 
            hide = nil
          end

          ##
          ## Support for Dynamic Issue (must be dynamic, these checks always run)
          ##
          if check[:dynamic_issue]
            issue = check[:dynamic_issue].call(data)
          else
            issue = nil
          end

          ##
          ## Support for Dynamic Task (must be dynamic, these checks always run)
          ##
          if check[:dynamic_task]
            task = check[:dynamic_task].call(data)
          else
            task = nil
          end

        end

        to_return = {
          "type" => check[:type],
          "name" => check[:name],
          "hide" => hide,
          "issue" => issue,
          "task" => task,
          "result" => result
        }
      end

    to_return
    end

end
end

# always include 
include Intrigue::Ident