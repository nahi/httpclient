body = ['abcdfghklmnop' * 100_000]
run Proc.new { |env|
  [200, {'Content-Type' => 'text/html'}, body]
}