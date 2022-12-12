# Эта бибилиотека понадобиться нам для шифрования
require 'openssl'

# Модель польлзователя.
#
# Каждый экземпляр этого класса - загруженный из БД инфа о конкретном юзере
class User < ApplicationRecord
	# Параметры для работы модуля шифрования паролей
	ITERATIONS = 20_000
	DIGEST = OpenSSL::Digest::SHA256.new

	# Виртуальное поле, которое не сохраняется в базу. Из него перед сохранением 
	# читается пароль, и сохранятеся в базу уже зашифрованная версия пароля в 
	# в реальные поля password_salt  и password_hash.
	attr_accessor :password

	# Эта команда добавляет связь с моделью Question на уровне объектов она же 
	# добавляет метод .questions к данному объекту.
	# 
	# Вспоминайте уроки про реляционные БД и связи между таблицами.
	# 
	# Когда мы вызываем метод questions у экземпляра класса User, рельсы
	# поймут это как просьбу найти в базе все объекты класса Questions со
	# значением user_id равынй user.id.
	has_many :questions

	# Валидация, которая проверяет, что поля email и username не пустые и не равны 
	# nil. Если на задан email и username, не бует сохранён в базу.
	validates :email, :username, presence: true

    # Валидация которая проверяет уникальность полей email и username. Если в 
    # базе данных уже есть записи с такими email и/или username, объект не будет 
    # сохранён в базу.
    validates :email, :username, uniqueness: true

    # Поле password нужно только при создании (create) нового юзера - регистации.
    # password_confirmation. Понадобиться при создании формы регистрации, чтобы 
    # снизить число ошибочно введённых паролей.
    validates :password, presence: true, on: :create

    # Валидация, которая проверяет совпадения значений полей password и
    # password_confirmation. Понадобится при создании формы регистрации, чтобы
    # снизить число ошибочно введенных паролей.
    validates_confirmation_of :password

    # Ошибки валидаций можно посмотреть методом errors.

    # Перед сохранением объекта в базу, создаём зашифрованный пароль, который 
    # будет храниться в БД.
    before_save :encrypt_password

    # Шифруем пароль, если он задан
    def encrypt_password
    	if password.present?
    		# Создаём т. н. "соль" - рандомная строка усложняющяя задачу хакерам по 
    		# взлому пароля, если даже у них окажется наша база данных.
    		self.password_salt = User.hash_to_string(OpenSSL::Random.random_bytes(16))

    		# Создаём хеш пароля - длинная уникальная строка, из которой невозможно 
    		# востановить исходный пароль. Однако, если правильный пароль у нас есть, 
    		# мы легко можем получить такуюже строку и сравнить её с той, что в базе.
            self.password_hash = User.hash_to_string(
            OpenSSL::PKCS5.pbkdf2_hmac(
            	password, password_salt, ITERATIONS, DIGEST.length, DIGEST
            	)
            )

            # Оба поля окажуться записанными в базу при сохранении (save). 
        end
    end

    # Служебный метод, преобразующий бинарную строку в 16-ричный формат,
    # для удобства хранения.
    def self.hash_to_string(password_hash)
    	password_hash.unpack('H*')[0]
    end

    # Основной метод для аутентификации юзера (логина). Проверяет email пароль
    # если пользователь с такой комбинацией есть в базе возвращает этого 
    # пользователя. Если нету - возвращает nil
    def self.authenticate(email, password)
      # Сперва находим кандидата по email
      user = find_by(email: email)

      # Если пользователь не найден, возвращаем nil
      return nil unless user.present?

      # Формируем хеш пароль из того, что передали в метод
      hashed_password = User.hash_to_string(
      	OpenSSL::PKCS5.pbkdf2_hmac(
      		password, user.password_salt, ITERATIONS, DIGEST.length, DIGEST
      		)
      	)

      	# Обратите внимание: сравнивается password_hash, а оригинальный пароль
      	# никогда и не сохраняется нигде. Если пароли совпали, возвращаем 
      	# пользователя.
      	return user if user.password_hash == hashed_password

      	# Иначе, возвращаем nil
      	nil 
    end 
end
