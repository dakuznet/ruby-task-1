require 'damerau-levenshtein'
require 'time'

file = ARGV[0]

candidates = Hash.new(0)
votes = []
known = []
candidate_to_times = Hash.new { |h,k| h[k] = [] }

start = Time.now

File.foreach(file).with_index do |line, idx|
  line =~ /candidate:\s+(.+)$/
  raw = $1.strip

  found = known.find { |k| DamerauLevenshtein.distance(raw, k) <= 3 }
  canonical = found || raw
  known << canonical unless found

  candidates[canonical] += 1
  votes << { line: line, candidate: canonical }

  if line =~ /time:\s+(.+?), ip:/
    time_str = $1
    time = Time.parse(time_str)
    candidate_to_times[canonical] << time
  end
end

ip_counts = Hash.new { |h,k| h[k] = Hash.new(0) }
votes.each do |v|
  if v[:line] =~ /ip:\s+([\d\.]+)/
    ip = $1
    ip_counts[v[:candidate]][ip] += 1
  end
end

suspicious_ip = ip_counts.map do |cand, ips|
  repeats = ips.values.map { |count| [count - 1, 0].max }.sum
  [cand, repeats]
end.select { |_, r| r > 0 }.sort_by { |_, r| -r }

def max_burst(times, window = 60)
  return 0 if times.empty?
  times = times.sort
  left = 0
  mb = 1
  (1...times.size).each do |right|
    while times[right] - times[left] >= window && left < right
      left += 1
    end
    mb = [mb, right - left + 1].max
  end
  mb
end

suspicious_burst = candidate_to_times.map do |cand, times|
  burst = max_burst(times)
  [cand, burst]
end.sort_by { |_, b| -b }

cheaters = []
top_ip = suspicious_ip.first
cheaters << top_ip if top_ip

top_burst = suspicious_burst.find { |c, _| c != (top_ip ? top_ip[0] : nil) }
cheaters << top_burst if top_burst

cheaters.each_with_index do |cheater, i|
  name, score = cheater
  type = (suspicious_ip.map(&:first).include?(name) ? "Много голосов с одного IP" : "Много голосов за 60 сек")
  puts "#{i + 1}. #{name} — подозреваемый (#{type} - #{score})"
end

puts "Время выполнения: #{(Time.now - start).round(3)} s"