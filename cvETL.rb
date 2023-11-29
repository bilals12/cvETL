# frozen_string_literal: true

require 'addressable/uri'
require 'csv'
require 'digest'
require 'fileutils'
require 'json'
require 'nokogiri'
require 'pry'

module cvETL

	# constants for content parsers
	CONTENT_PARSERS = {
		css: Nokogiri::CSS,
		csv: CSV,
		html: Nokogiri::HTML,
		json: JSON,
		plain: nil,
		xml: Nokogiri::XML
	}.freeze

	# read + parse file content based on specified type
	# @param [Pathname] file - path to file
	# @param [Symbol] type - type of data
	# @return [Object] - parsed content
	def self.content(file, type)
		file_content = File.read(file)
		parser = CONTENT_PARSERS[type.to_sym]
		parser ? parser.parse(file_content) : file_content
	end

	# update + format content of JSON
	# @param [Pathname] path - path to JSON
	# @param [Hash] data - date written to file
	def self.dump_cache(path, data)
		options = { indent: ' ', object_nl: "\n", array_nl: "\n"}
		File.write(path, JSON.pretty_generate(data, options))
	end

	# generate SHA256 hash of file contents
	def self.file_hash(file)
		Digest::SHA256.hexdigest(File.read(file))
	end

	# construct file path from URL
	def self.file_path(url, dir = nil, type = nil)
		path_elements = [url.host, *url.path.split('/'), *url.fragment&.split('&')&.[](1)&.split(/[\\,\/,\|,\?]/)]
		path_elements << url.query_values_to_h.keys.take(3).join('_') if url.query_values_to_h.size > 3
		path = path_elements.compact.reject(&:empty?).join('_')
		path.concat(".#{type}") unless path.match?(/\.#{type}\z/)
		dir ? Pathname.new(File.join(dir, path)) : Pathname.new(path)
	end

	# convert array of elements to sentence
	def self.grammarize(elements)
		return '' if elements.empty?
		elements.size == 1 ? elements.first.to_s : "#{elements[0...-1].join(', ')} and #{elements.last}"
	end

	# init hash with provided keys + default value
	def self.init_hash(keys, value = true)
		keys.map { |key| [key, value] }.to_h
	end

	# load JSON data from file
	def self.load_cache(path)
		return {} unless File.exist?(path) && !File.empty?(path)
		JSON.parse(File.read(path))
	end

	# normalize string by std encoding + remove extra chars
	def self.normalize(str)
		str.encode('ASCII', invalie: :replace, undef: :replace, replace: '')
		.encode('UTF-8').strip.gsub(/\s+/, ' ')
	end

	# list sub-modules + classes within major module
	def self.subordinates(namespace, classes: false)
		constants = namespace.constants.map(&namespace.method(:const_get))
		classes ? constants.grep(Class) : constants
	end


	# return unix timestamp with optional delay
	def self.time_stamp(delay: 0)
		sleep(delay)
		Time.now.to_i.to_s
	end

	# map versions of application to fixed version
	def self.vuln_ranges(app, affected, fixed)
		sorted_affected = affected_sort
		return [{}, sorted_affected] if affected.empty? && fixed.empty?

		ranges = fixed.sort.each_with_object({}) do |higher, acc|
			lower, remaining = sorted_affected.partition { |v| v < higher }
			acc[higher] = lower if acc.empty? || lower.any?
		end

		[ranges, sorted_affected]
	end

	# generate temporary vuln code for testing
	def self.vulncode(advisory_id)
		Digest::SHA256.hexdigest(advisory_id)
	end

end
