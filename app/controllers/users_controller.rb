# Будет создавать новых пользователей , регистрация, авторизация
class UsersController < ApplicationController

  def show
  	@time = Time.now
  	@hello = "Привет, Мишаня!"
  end
end
