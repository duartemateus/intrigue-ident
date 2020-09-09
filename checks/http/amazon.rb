module Intrigue
module Ident
module Check
class Amazon < Intrigue::Ident::Check::Base

  def generate_checks(url)
    [
      {
        :type => "fingerprint",
        :category => "service",
        :tags => ["Load Balancer", "Hosting", "WAF", "IaaS"],
        :url => "https://aws.amazon.com/blogs/aws/aws-web-application-firewall-waf-for-application-load-balancers/",
        :references => ["https://stackoverflow.com/questions/49197688/is-the-most-recent-awsalb-cookie-required-aws-elb-application-load-balancer"],
        :vendor => "Amazon",
        :product => "Application Load Balancer",
        :version => nil,
        :match_type => :content_cookies,
        :match_content =>  /AWSALB=/,
        :match_details =>"amazon App LB cookie (sticky sessions)",
        :hide => false,
        :paths => ["#{url}"],
        :inference => false
      },
      {
        :type => "fingerprint",
        :category => "service",
        :tags => ["CDN", "Hosting", "WAF", "IaaS"],
        :vendor => "Amazon",
        :product =>"Cloudfront",
        :version => nil,
        :match_details =>"cloudfront cache header",
        :match_type => :content_headers,
        :match_content =>  /via:.*.cloudfront.net \(CloudFront\)/,
        :hide => false,
        :paths => ["#{url}"],
        :inference => false
      },
      {
        :type => "fingerprint",
        :category => "service",
        :tags => ["CDN", "Hosting", "WAF", "IaaS"],
        :vendor => "Amazon",
        :product =>"Cloudfront",
        :version => nil,
        :match_details =>"cloudfront cache header",
        :match_type => :content_headers,
        :match_content =>  /x-cache:.*cloudfront/i,
        :hide => false,
        :paths => ["#{url}"],
        :inference => false
      },
      {
        :type => "fingerprint",
        :category => "service",
        :tags => ["CDN", "Hosting","WAF", "IaaS"],
        :vendor => "Amazon",
        :product =>"Cloudfront",
        :match_details =>"no configured hostname error condition",
        :version => nil,
        :match_type => :content_body,
        :match_content => /ERROR: The request could not be satisfied/,
        :dynamic_hide => lambda{ |x| 
          return true if _uri_match(x,/cloudfront.net/)       || 
                         _uri_match(x,/\d+.\d+.\d+.\d+:/) 
        },
        :paths => ["#{url}"],
        :inference => false
      },
      {
        :type => "fingerprint",
        :category => "service",
        :tags => ["CDN", "Hosting","WAF", "IaaS"],
        :vendor => "Amazon",
        :product =>"Cloudfront",
        :match_details =>"cloudfront error",
        :version => nil,
        :match_type => :content_body,
        :match_content => /If you provide content to customers through CloudFront, you can find steps to troubleshoot and help prevent this error by reviewing the CloudFront documentation./im,
        :dynamic_hide => lambda{ |x| 
          return true if _uri_match(x,/cloudfront.net/)       || 
                         _uri_match(x,/\d+.\d+.\d+.\d+:/) 
        },
        :paths => ["#{url}"],
        :inference => false
      },
      {
        :type => "fingerprint",
        :category => "service",
        :tags => ["CDN", "Hosting","WAF", "IaaS"],
        :vendor => "Amazon",
        :product =>"Cloudfront",
        :match_details =>"Cloudfront 403",
        :version => nil,
        :match_type => :content_body,
        :match_content => /<H1>403 ERROR<\/H1>\n<H2>The request could not be satisfied.<\/H2>\n.*Generated by cloudfront \(CloudFront\)/im,
        :dynamic_hide => lambda{ |x| 
          return true if _uri_match(x,/cloudfront.net/)       || 
                         _uri_match(x,/\d+.\d+.\d+.\d+:/) 
        },
        :paths => ["#{url}"],
        :inference => false
      },
      {
        :type => "fingerprint",
        :category => "service",
        :tags => ["CDN", "Hosting","WAF", "IaaS"],
        :vendor => "Amazon",
        :product =>"Cloudfront",
        :match_details =>"generic error",
        :version => nil,
        :match_type => :content_headers,
        :match_content =>  /Error from cloudfront/,
        :dynamic_hide => lambda{ |x| 
          return true if _uri_match(x,/cloudfront.net/)       || 
                         _uri_match(x,/\d+.\d+.\d+.\d+:/) 
        },
        :paths => ["#{url}"],
        :inference => false
      },
      {
        :type => "fingerprint",
        :category => "service",
        :tags => ["CDN", "Hosting","WAF", "IaaS"],
        :vendor => "Amazon",
        :product =>"Cloudfront",
        :match_details =>"x-amz-cf-pop header",
        :version => nil,
        :match_type => :content_headers,
        :match_content =>  /^x-amz-cf-pop:.*/i,
        :hide => false,
        :paths => ["#{url}"],
        :inference => false
      },
      { 
        :type => "fingerprint",
        :category => "service",
        :tags => ["CDN", "Hosting","WAF", "IaaS"],
        :vendor => "Amazon",
        :product =>"Cloudfront",
        :match_details =>"x-amz-cf-id header",
        :version => nil,
        :match_type => :content_headers,
        :match_content =>  /^x-amz-cf-id:.*/i,
        :hide => false,
        :paths => ["#{url}"],
        :inference => false
      },
      {
        :type => "fingerprint",
        :category => "service",
        :tags => ["CDN", "Hosting", "WAF", "IaaS"],
        :vendor => "Amazon",
        :product =>"Cloudfront",
        :match_details =>"generic error",
        :version => nil,
        :match_type => :content_headers,
        :match_content => /^x-cache: Error from cloudfront$/i,
        :dynamic_hide => lambda{ |x| 
          return true if _uri_match(x,/cloudfront.net/)       || 
                         _uri_match(x,/\d+.\d+.\d+.\d+:/) 
        },
        :paths => ["#{url}"],
        :inference => false
      },
      {
        :type => "fingerprint",
        :category => "service",
        :tags => ["CDN", "Hosting", "WAF", "IaaS"],
        :vendor => "Amazon",
        :product =>"Cloudfront",
        :match_details =>"403 error condition",
        :version => nil,
        :match_type => :content_body,
        :match_content => /<h1>403 Forbidden<\/h1><\/center>\n<hr><center>cloudfront/,
        :dynamic_hide => lambda{ |x| 
          return true if _uri_match(x,/cloudfront.net/)       || 
                         _uri_match(x,/\d+.\d+.\d+.\d+:/) 
        },
        :paths => ["#{url}"],
        :inference => false
      },
      {
        :type => "fingerprint",
        :category => "service",
        :tags => ["Load Balancer", "Hosting", "IaaS"],
        :url => "https://aws.amazon.com/elasticloadbalancing/",
        :vendor => "Amazon",
        :product => "Elastic Load Balancer",
        :version => nil,
        :match_type => :content_headers,
        :match_content =>  /awselb\/\d.\d/,
        :match_details =>"error page",
        :dynamic_hide => lambda{ |x| 
          return true if _uri_match(x,/amazonaws.com/)       || 
                         _uri_match(x,/\d+.\d+.\d+.\d+:/) 
        },
        :dynamic_version => lambda { |x| _first_header_capture(x,/awselb\/(\d.\d)/) },
        :paths => ["#{url}"],
        :inference => false
      },
      {
        :type => "fingerprint",
        :category => "service",
        :tags => ["Load Balancer", "Hosting", "IaaS"],
        :url => "https://aws.amazon.com/blogs/aws/aws-web-application-firewall-waf-for-application-load-balancers/",
        :vendor => "Amazon",
        :product => "Elastic Load Balancer",
        :version => nil,
        :match_type => :content_cookies,
        :match_content =>  /AWSELB=/,
        :match_details =>"amazon elastic cookie",
        :hide => false,
        :paths => ["#{url}"],
        :inference => false
      },
      {
        :type => "fingerprint",
        :category => "operating_system",
        :tags => ["OS", "IaaS"],
        :vendor => "Amazon",
        :product =>"Linux",
        :match_details =>"nginx test page",
        :version => nil,
        :match_type => :content_title,
        :match_content => /^Test Page for the Nginx HTTP Server on the Amazon Linux AMI$/,
        :hide => false,
        :paths => ["#{url}"],
        :inference => false
      },
      {
        :type => "fingerprint",
        :category => "operating_system",
        :tags => ["OS", "IaaS"],
        :vendor => "Amazon",
        :product =>"Linux",
        :match_details =>"nginx test page",
        :version => nil,
        :match_type => :content_title,
        :match_content => /^Test Page for the Nginx HTTP Server on Amazon Linux$/,
        :hide => false,
        :paths => ["#{url}"],
        :inference => false
      },
      {
        :type => "fingerprint",
        :category => "service",
        :tags => ["Web Server", "Hosting", "IaaS"],
        :vendor => "Amazon",
        :product =>"S3",
        :match_details =>"server header",
        :version => nil,
        :match_type => :content_headers,
        :match_content => /server: AmazonS3/i,
        :hide => false,
        :paths => ["#{url}"],
        :inference => false
      },
      {
        :type => "fingerprint",
        :category => "service",
        :tags => ["Web Server", "Hosting", "IaaS"],
        :vendor => "Amazon",
        :product =>"S3",
        :match_details =>"replication status header",
        :version => nil,
        :match_type => :content_headers,
        :match_content => /^x-amz-replication-status: .*$/i,
        :hide => false,
        :paths => ["#{url}"],
        :inference => false
      }
    ]
  end
end
end
end
end
