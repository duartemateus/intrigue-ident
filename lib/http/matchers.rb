module Intrigue
module Ident
module Http
module Matchers

  include Intrigue::Ident::Http
  include Intrigue::Ident::Content::Http

  def match_http_response_hash(check,hash)

    # save off the generator string
    generator_match = "#{hash[:response_body]}".match(/<meta name=\"?generator\"? content=\"?(.*?)\"?\/>/i)
    generator_string = generator_match.captures.first.gsub("\"","") if generator_match

    # save off the title string
    title_match = "#{hash[:response_body]}".match(/<title>(.*?)<\/title>/i)
    title_string = title_match.captures.first.strip if title_match

    # grab the set cookie header
    set_cookie_header = "#{(hash[:response_headers]||[]).select{|x| x =~ /^set-cookie:(.*)/i}.first}".gsub("set-cookie:","").strip

    data = hash.merge({
      "details" =>  {
        "hidden_response_data" => "#{hash[:response_body]}",
        "start_url" => "#{hash[:start_url]}",
        "final_url" => "#{hash[:final_url]}",
        "headers" => hash[:response_headers], # this is a hash and we need an array!
        "certificate" => hash[:certificate] || {},
        "cookies" => set_cookie_header,
        "generator" => generator_string,
        "title" => title_string
      }
    })

    #puts "matching #{check} against: #{data}"

  match_uri_hash(check,data)
  end

  def match_browser_response_hash(check,browser_response_hash)
    data = {
      "details" =>  {
        "hidden_response_data_rendered" => "#{browser_response_hash[:rendered]}",
        "start_url" => "#{browser_response_hash[:start_url]}",
        "final_url" => "#{browser_response_hash[:final_url]}",
        "headers" => [],
        "cookies" => "",
        "generator" => "",
        "title" => "#{browser_response_hash[:title]}",
      }
    }

    match_uri_hash(check,data)
  end

  # Matches a text http response
  def match_http_response_text(check,http_response_text)

    # first convert to intrigue uri format

    # grab headers
    header_part = http_response_text.split(/\n\n/).first
    body_part = http_response_text.split(/\n\n/).last

    headers = header_part.split("\n");
    body = body_part

    # TODO - fix to only grab content!!!!
    cookies = headers.select{|x| x =~ /^set-cookie:(.*)/i }

    ### grab the page attributes
    match = body.match(/<title>(.*?)<\/title>/i)
    title = match.captures.first if match

    match = response.body.match(/<meta name=\"?generator\"? content=\"?(.*?)\"?\/?>/i)
    generator = match.captures.first.gsub("\"","") if match

    # rest is a response
    # save title
    # save Cookies
    # save scripts ?
    data = {
      "details" =>  {
        "hidden_response_data" => body,
        "headers" => headers,
        "cookies" => cookies,
        "generator" => generator,
        "title" => title
      }
    }

    match_uri_hash(check,data)
  end

  def match_uri_hash(check, data)
    return nil unless check && data

    # data[:body] => page body
    # data[:headers] => block of text with headers, one per line
    # data[:cookies] => set_cookie header
    # data[:title] => parsed page title
    # data[:generator] => parsed meta generator tag
    # data[:body_md5] => md5 hash of the body
    # if type "content", do the content check

    if check[:type] == "fingerprint"
      if check[:match_type] == :content_body
        match = _construct_match_response(check,data) if _body(data) =~ check[:match_content]
      elsif check[:match_type] == :content_body_raw
        match = _construct_match_response(check,data) if _body_raw(data) =~ check[:match_content]
      elsif check[:match_type] == :content_dom
        match = _construct_match_response(check,data) if _body_rendered(data) =~ check[:match_content]
      elsif check[:match_type] == :content_headers
        match = _construct_match_response(check,data) if _headers(data) =~ check[:match_content]
      elsif check[:match_type] == :content_cookies
        match = _construct_match_response(check,data) if _cookies(data) =~ check[:match_content]
      elsif check[:match_type] == :content_generator
        match = _construct_match_response(check,data) if _generator(data) =~ check[:match_content]
      elsif check[:match_type] == :content_title
        match = _construct_match_response(check,data) if _title(data) =~ check[:match_content]
      elsif check[:match_type] == :content_cert_subject
        match = _construct_match_response(check,data) if _cert_subject(data) =~ check[:match_content]
      elsif check[:match_type] == :content_cert_issuer
        match = _construct_match_response(check,data) if _cert_subject(data) =~ check[:match_content]
      elsif check[:match_type] == :checksum_body
        match = _construct_match_response(check,data) if _body_raw_checksum(data) == check[:match_content]
      end
    elsif check[:type] == "content"
      match = _construct_match_response(check,data)
    end
  match
  end

end
end
end
end