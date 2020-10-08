<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "gruppa".
 *
 * @property int $gruppa_id
 * @property string $name
 * @property int $special_id
 * @property string $date_begin
 * @property string|null $date_end
 *
 * @property Special $special
 * @property LessonPlan[] $lessonPlans
 * @property Student[] $students
 */
class Gruppa extends \yii\db\ActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return 'gruppa';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['name', 'special_id', 'date_begin'], 'required'],
            [['special_id'], 'integer'],
            [['date_begin', 'date_end'], 'safe'],
            [['name'], 'string', 'max' => 50],
            [['special_id'], 'exist', 'skipOnError' => true, 'targetClass' => Special::className(), 'targetAttribute' => ['special_id' => 'special_id']],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'gruppa_id' => 'Gruppa ID',
            'name' => 'Name',
            'special_id' => 'Special ID',
            'date_begin' => 'Date Begin',
            'date_end' => 'Date End',
        ];
    }

    /**
     * Gets query for [[Special]].
     *
     * @return \yii\db\ActiveQuery
     */
    public function getSpecial()
    {
        return $this->hasOne(Special::className(), ['special_id' => 'special_id']);
    }

    /**
     * Gets query for [[LessonPlans]].
     *
     * @return \yii\db\ActiveQuery
     */
    public function getLessonPlans()
    {
        return $this->hasMany(LessonPlan::className(), ['gruppa_id' => 'gruppa_id']);
    }

    /**
     * Gets query for [[Students]].
     *
     * @return \yii\db\ActiveQuery
     */
    public function getStudents()
    {
        return $this->hasMany(Student::className(), ['gruppa_id' => 'gruppa_id']);
    }
}
