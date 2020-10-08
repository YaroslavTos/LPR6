<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "otdel".
 *
 * @property int $otdel_id
 * @property string $name
 * @property int $active
 *
 * @property Special[] $specials
 * @property Teacher[] $teachers
 */
class Otdel extends \yii\db\ActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return 'otdel';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['name'], 'required'],
            [['active'], 'integer'],
            [['name'], 'string', 'max' => 50],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'otdel_id' => 'Otdel ID',
            'name' => 'Name',
            'active' => 'Active',
        ];
    }

    /**
     * Gets query for [[Specials]].
     *
     * @return \yii\db\ActiveQuery
     */
    public function getSpecials()
    {
        return $this->hasMany(Special::className(), ['otdel_id' => 'otdel_id']);
    }

    /**
     * Gets query for [[Teachers]].
     *
     * @return \yii\db\ActiveQuery
     */
    public function getTeachers()
    {
        return $this->hasMany(Teacher::className(), ['otdel_id' => 'otdel_id']);
    }

    public function getSubject()
    {
        return $this->hasMany(Teacher::className(), ['otdel_id' => 'otdel_id']);
    }
}
