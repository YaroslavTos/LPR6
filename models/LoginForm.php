<?php

namespace app\models;

use Yii;
use yii\base\Model;


class LoginForm extends Model
{
    public $username;
    public $password;


    private $_user = false;


    /**
     * @return array the validation rules.
     */
    public function rules()
    {
        return [
            [['username', 'password'], 'required'],
            ['password', 'validatePassword'],

        ];
    }


    public function validatePassword($attribute, $params)
    {
        if (!$this->hasErrors()) {
            $user = $this->getUser();
            if (!$user || !$user->validatePassword($this->
                password)) {
                $this->addError($attribute, 'Incorrect username or password.');
            }
        }
    }

    public function auth()
    {
        if ($this->validate()) {
            $this->_user->generateToken(time() + 3600 * 24);
            return $this->_user->save() ? $this->user->
            tokenInfo() : null;
        } else {
            return null;
        }
    }


    public function getUser()
    {
        if ($this->_user === false) {
            $this->_user = User::findByUsername($this->username);
        }
        return $this->_user;
    }
}
