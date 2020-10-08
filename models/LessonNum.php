<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "lesson_num".
 *
 * @property int $lesson_num_id
 * @property string $name
 * @property string $time_lesson
 *
 * @property Schedule[] $schedules
 */
class LessonNum extends \yii\db\ActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return 'lesson_num';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['name', 'time_lesson'], 'required'],
            [['time_lesson'], 'safe'],
            [['name'], 'string', 'max' => 50],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'lesson_num_id' => 'Lesson Num ID',
            'name' => 'Name',
            'time_lesson' => 'Time Lesson',
        ];
    }

    /**
     * Gets query for [[Schedules]].
     *
     * @return \yii\db\ActiveQuery
     */
    public function getSchedules()
    {
        return $this->hasMany(Schedule::className(), ['lesson_num_id' => 'lesson_num_id']);
    }
}
