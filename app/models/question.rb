class Question < ApplicationRecord

    belongs_to :user

	validates :text, :user, presence: true

	# Ошибки валидаций можно посмотреть методом errors.

	# Демонтрация жизненного цикла объекта навесили на все популярные коллбэки
	# вои методы.
	# before_validation :before_validation
	# after_validation :after_validation

	# before_save :before_save
	# after_save :after_save

	# before_create :before_create
	# after_create :after_create

	# before_update :before_update
	# after_update :after_update

	# before_destroy :before_destroy
	# after_destroy :after_destroy
    
    # Второй метод написания кода

    # %w(validation save create update destroy).each do |action|
    #   %w(before after).each do |time|
    #     define_method("#{time}_#{action}") do
    #       puts "******> #{time} #{action}"
    #     end
    #   end
    # end

	# динамически сгенерируем пару методов для каждого
	# действия, используя возможности руби
	# ['validation', 'save', 'create', 'update', 'destroy'].each do |action|
	#   ['before', 'after'].each do |time|
	#     define_method("#{time}_#{action}") do 
	#       puts "*****> #{time} #{action}"
	#     end
	#   end
	# end
end
