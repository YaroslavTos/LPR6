<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "teacher".
 *
 * @property int $user_id
 * @property int $otdel_id
 *
 * @property LessonPlan[] $lessonPlans
 * @property Otdel $otdel
 * @property User $user
 */
class Teacher extends \yii\db\ActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return 'teacher';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['otdel_id'], 'required'],
            [['otdel_id'], 'integer'],
            [['otdel_id'], 'exist', 'skipOnError' => true, 'targetClass' => Otdel::className(), 'targetAttribute' => ['otdel_id' => 'otdel_id']],
            [['user_id'], 'exist', 'skipOnError' => true, 'targetClass' => User::className(), 'targetAttribute' => ['user_id' => 'user_id']],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'user_id' => 'User ID',
            'otdel_id' => 'Otdel ID',
        ];
    }

    /**
     * Gets query for [[LessonPlans]].
     *
     * @return \yii\db\ActiveQuery|\app\models\queries\LessonPlanQuery
     */
    public function getLessonPlans()
    {
        return $this->hasMany(LessonPlan::className(), ['user_id' => 'user_id']);
    }

    /**
     * Gets query for [[Otdel]].
     *
     * @return \yii\db\ActiveQuery|\app\models\queries\OtdelQuery
     */
    public function getOtdel()
    {
        return $this->hasOne(Otdel::className(), ['otdel_id' => 'otdel_id']);
    }

    /**
     * Gets query for [[User]].
     *
     * @return \yii\db\ActiveQuery|\app\models\queries\UserQuery
     */
    public function getUser()
    {
        return $this->hasOne(User::className(), ['user_id' => 'user_id']);
    }

    /**
     * {@inheritdoc}
     * @return \app\models\queries\TeacherQuery the active query used by this AR class.
     */
    public static function find()
    {
        return new \app\models\queries\TeacherQuery(get_called_class());
    }




    public function loadAndSave($bodyParams)
    {
        $user = ($this->isNewRecord) ? new User() :
            User::findOne($this->user_id);
        if ($user->load($bodyParams, '') && $user->save()) {
            if ($this->isNewRecord) {
                $this->user_id = $user->user_id;
            }
            if ($this->load($bodyParams, '') && $this->save()) {
                return true;
            }
        }
        return false;
    }

    public function fields($bodyParams)
    {
        $fields = parent::fields();
        return array_merge($fields, [
            'lastname' => function () { return $this->user->lastname;},
            'firstname' => function () { return $this->user->firstname;},
            'patronymic' => function () { return $this->user->patronymic;},
            'login' => function () { return $this->user->login;},
            'gender_id' => function () { return $this->user->gender_id;},
            'genderName' => function () { return $this->user->gender->name;},
            'birthday' => function () { return $this->user->birthday;},
            'roleName' => function () { return $this->user->roleName;},
            'active' => function () { return $this->user->active;},
            'otdelName' => function () { return $this->otdel->name;},
            ]);
    }
}
