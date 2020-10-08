<?php



use yii\web\IdentityInterface;


class User extends \yii\base\BaseObject implements \yii\web\IdentityInterface
{
    const STATUS_DELETED=0;
    const STATUS_ACTIVE=1;

    public $id;
    public $username;
    public $password;
    public $authKey;
    public $accessToken;
    public $role;

    private static $users = [
        '100' => [
            'id' => '100',
            'username' => 'admin',
            'password' => 'admin',
            'authKey' => 'test100key',
            'accessToken' => '100-token',
        ],
        '101' => [
            'id' => '101',
            'username' => 'demo',
            'password' => 'demo',
            'authKey' => 'test101key',
            'accessToken' => '101-token',
        ],
    ];


    /**
     * {@inheritdoc}
     */


    /**
     * Finds user by username
     *
     * @param string $username
     * @return static|null
     */


    /**
     * {@inheritdoc}
     */


    /**
     * {@inheritdoc}
     */


    /**
     * {@inheritdoc}
     */


    /**
     * Validates password
     *
     * @param string $password password to validate
     * @return bool if password provided is valid for current user
     */


    public function validatePassword($password)
    {
        return Yii::$app->getSecurity()
            ->validatePassword($password, $this->pass);
    }

    public function getId()
    {
        return $this->getPrimaryKey();
    }


    public static function findIdentity($id)
    {
        return static::findOne(['user_id' => $id, 'active' =>
            self::STATUS_ACTIVE]);
    }

    /**
     * {@inheritdoc}
     */
    public static function findIdentityByAccessToken($token, $type = null)
    {
        return static::find()
            ->andWhere(['token' => $token])
            ->andWhere(['>', 'expired_at', time()])
            ->one();
    }

    public static function findByUsername($username)
    {
        return static::findOne(['login' => $username, 'active'
        => self::STATUS_ACTIVE]);
    }


    public function generateToken($expire)
    {
        $this->expired_at = $expire;
        $this->token = Yii::$app->security
            ->generateRandomString();
    }


    public function tokenInfo()
    {
        return [
            'token' => $this->token,
            'expiredAt' => $this->expired_at,
            'fio' => $this->lastname.' '.$this->firstname. '
'.$this->patronymic,
            'roles' => Yii::$app->authManager->
            getRolesByUser($this->user_id)
        ];
    }


    public function logout()
    {
        $this->token = null;
        $this->expired_at = null;

        return $this->save(false);
    }

    public function getAuthKey()
    {

    }

    public function validateAuthKey($authKey)
    {

    }





    public function getGender()
    {
        return $this->hasOne(Gender::className(),['gender_id' =>
            'gender_id']);
    }

    public function rules()
    {
        return [
            [['lastname', 'firstname', 'gender_id', 'role'],
                'required'],
            [['gender_id', 'active', 'expired_at'],
                'integer'],
            ['birthday', 'date', 'format' => 'yyyy-MM-dd'],
            [['lastname', 'firstname', 'patronymic',
                'login'], 'string', 'max' => 50],
            [['pass', 'token'], 'string', 'max' => 255],
            ['login', 'unique', 'message' => 'login
            invalid'],
        ];
    }

    public function afterSave($insert , $changedAttributes)
    {
        parent::afterSave($insert, $changedAttributes);
        $auth = Yii::$app->authManager;
        $roles = $auth->getRoles();
        if (array_key_exists($this->role, $roles)) {
            $role = $auth->getRole($this->role);
            $auth->revokeAll($this->user_id);
            $auth->assign($role, $this->user_id);
        }
    }


    public function fields()
    {
        $fields = parent::fields();
        unset($fields['pass'], $fields['token'],
            $fields['expired_at']);
        return array_merge($fields, [
            'genderName' => function () { return $this->gender->name;},
            'roleName' => function () { return $this->roleName; },
        ]);
    }


    public function getRoleName()
    {
        $roles = Yii::$app->authManager
            ->getRolesByUser($this->user_id);
        $roleName = array_key_first($roles);

        return $roles[$roleName]->description;
    }

    public function afterValidate()
    {
        if ($this->pass) {
            $this->setHashPassword($this->pass);
        }

        return true;
    }

    public function setHashPassword($password)
    {
        $this->pass = Yii::$app->getSecurity()->generatePasswordHash($password);
    }

}
