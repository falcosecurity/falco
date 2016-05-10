#!/usr/bin/env ruby

require 'nokogiri'
require 'open-uri'
require 'fileutils'

# The following lines of code get all the wiki pages and get the html content for each and every one of them.
# Since Github accepts quite some combinations of urls (wiki/Sysdig Overview == wiki/Sysdig-Overview == wiki/sysdig overview == ...)
#   and obviously Github Pages don't, I'll need to normalize every page and regexp a little bit some links.
#   The sysdig.org wiki will be composed by every article written in lower case with dashes instead of spaces.
#   Every article will be placed inside an index.html file inside of its corresponding folder to prettify the urls.
# Once run this script the wiki folder will be updated and a commit & push will deploy the new version live.

puts 'Cleaning up ...'

# Cleanups, while keeping wiki directory
FileUtils.rm_rf(Dir.glob('wiki/*'))

puts 'Getting wiki pages list ...'

doc = Nokogiri::HTML open 'https://github.com/draios/sysdig/wiki/_pages'
pages = { }

doc.css('#wiki-content .content a').each do |link|
    # Convert every link to lower case links
    href = 'https://github.com' + link.attr('href').downcase
    # Bad thing just to get the title
    name = href.slice 38, href.length - 37

    # This is going to be the index.html page
    name = 'index' if name == nil

    pages[name] = href
end

throw "[update-ruby] Cannot get index pages" if pages.length <= 0

puts 'Getting each page\'s content ...'

pages.each_pair do |name, href|
    puts '... ' + name

    page = Nokogiri::HTML open href

    # The wiki title is outside the main content
    title = page.css('h1.instapaper_title').inner_html

    throw "[update-ruby] Cannot get title for [" + name + "]" if title == nil || title.length <= 0

    # Main content
    html = page.css('div.markdown-body').inner_html

    # Remove the first parts of the wiki homepage
    if name == 'index'
        token = 'Sysdig Documentation Wiki</h2>'
        index = html.index token
        html  = html.slice index + token.length, html.length if index != nil

        title = 'Sysdig Documentation Wiki'
    end

    # Remove tracking link ("![](https://ga-beacon.appspot.com/UA-XXXXXXXX-X/sysdig/page-name?pixel)")
    # <img src="https://camo.githubusercontent.com/XXXXX" alt="" data-canonical-src="https://ga-beacon.appspot.com/UA-XXXXXXXX-X/sysdig/page-name?pixel" style="max-width:100%;">
    html.gsub! /<img .*? data-canonical-src="https:\/\/ga-beacon\.appspot\.com\/.*?>/, ''

    # Since all the urls are "wiki/..." we can point to them directly
    html.gsub! 'href="wiki', 'href="{{ site.baseurl }}wiki'
    html.gsub! 'href="https://github.com/draios/sysdig/wiki', 'href="{{ site.baseurl }}wiki'
    # Make anchors work
    html.gsub! 'name="user-content-', 'name="'
    html.gsub! 'href="#wiki-', 'href="#'
    # Make wiki links work
    html.gsub! /href="([^(http|#|\{\{|mailto)])/, 'href="{{ site.baseurl }}wiki/\1'
    # Every link must be in lower case
    html.gsub!(/href="\{\{ site\.baseurl \}\}wiki\/([^"]+(?="))"/) { "href=\"{{ site.baseurl }}wiki/#{$1.downcase}\"" }
    # Convert spaces into dashes in wiki urls
    html.gsub!(/href="\{\{ site.baseurl \}\}wiki\/([^"]+(?="))"/) { "href=\"{{ site.baseurl }}wiki/#{$1.gsub! /(%20| )/, '-'}\"" }

    throw "[update-ruby] Cannot get main content for [" + name + "]" if html == nil || title.length <= 0

    # Use the wiki layout which inherits from the default layout
    html = "---
layout: wiki
title: Wiki | " + title + "
slug: wiki
wiki-title: " + title + "
wiki-url: " + href + "
---
" + html

    # Index is the starting point
    if name == 'index'
        File.open('wiki/index.html', 'w') { |f| f.write(html) }
    # Otherwise create for each page a folder to prettify urls and make them semi-consistent with github wiki
    else
        Dir.mkdir('wiki/' + name)
        File.open('wiki/' + name + '/index.html', 'w') { |f| f.write(html) }
    end
end

puts 'Done'
