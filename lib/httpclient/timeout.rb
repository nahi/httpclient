require 'timeout'


module Timeout

  class TimeoutScheduler
    class Period
      attr_reader :thread, :time, :ex

      def initialize(thread, time, ex)
        @thread, @time, @ex = thread, time, ex
      end
    end

    def initialize
      @pool = {}
      @next = nil
      @thread = start_timer_thread
      Thread.pass while @thread.status != 'sleep'
    end

    def register(thread, sec, ex)
      period = Period.new(thread, Time.now + sec, ex || Timeout::Error)
      @pool[period] = period
      if @next.nil? or period.time < @next
        @thread.wakeup
      end
      period
    end

    def cancel(period)
      @pool.delete(period)
    end

  private

    def start_timer_thread
      Thread.new {
        while true
          if @pool.empty?
            @next = nil
            sleep
          else
            id, min = @pool.min { |a, b| a[1].time <=> b[1].time }
            @next = min.time
            sec = @next - Time.now
            if sec > 0
              sleep(sec)
            end
          end
          now = Time.now
          @pool.each do |id, period|
            if period.time < now
              period.thread.raise(period.ex, 'execution expired') if period.thread.alive?
              cancel(period)
            end
          end
        end
      }
    end
  end

  TIMEOUT_SCHEDULER = TimeoutScheduler.new
end

def timeout(sec, ex = nil, &block)
  return yield if sec == nil or sec.zero?
  begin
    period = Timeout::TIMEOUT_SCHEDULER.register(Thread.current, sec, ex)
    yield(sec)
  ensure
    Timeout::TIMEOUT_SCHEDULER.cancel(period)
  end
end
