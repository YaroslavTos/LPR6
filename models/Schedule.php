<?php

namespace app\models;

use Yii;

/**
 * This is the model class for table "schedule".
 *
 * @property int $schedule_id
 * @property int $lesson_plan_id
 * @property int $day_id
 * @property int $lesson_num_id
 * @property int $classroom_id
 *
 * @property Classroom $classroom
 * @property Day $day
 * @property LessonNum $lessonNum
 * @property LessonPlan $lessonPlan
 */
class Schedule extends \yii\db\ActiveRecord
{
    /**
     * {@inheritdoc}
     */
    public static function tableName()
    {
        return 'schedule';
    }

    /**
     * {@inheritdoc}
     */
    public function rules()
    {
        return [
            [['lesson_plan_id', 'day_id', 'lesson_num_id', 'classroom_id'], 'required'],
            [['lesson_plan_id', 'day_id', 'lesson_num_id', 'classroom_id'], 'integer'],
            [['classroom_id'], 'exist', 'skipOnError' => true, 'targetClass' => Classroom::className(), 'targetAttribute' => ['classroom_id' => 'classroom_id']],
            [['day_id'], 'exist', 'skipOnError' => true, 'targetClass' => Day::className(), 'targetAttribute' => ['day_id' => 'day_id']],
            [['lesson_num_id'], 'exist', 'skipOnError' => true, 'targetClass' => LessonNum::className(), 'targetAttribute' => ['lesson_num_id' => 'lesson_num_id']],
            [['lesson_plan_id'], 'exist', 'skipOnError' => true, 'targetClass' => LessonPlan::className(), 'targetAttribute' => ['lesson_plan_id' => 'lesson_plan_id']],
        ];
    }

    /**
     * {@inheritdoc}
     */
    public function attributeLabels()
    {
        return [
            'schedule_id' => 'Schedule ID',
            'lesson_plan_id' => 'Lesson Plan ID',
            'day_id' => 'Day ID',
            'lesson_num_id' => 'Lesson Num ID',
            'classroom_id' => 'Classroom ID',
        ];
    }

    /**
     * Gets query for [[Classroom]].
     *
     * @return \yii\db\ActiveQuery|\app\models\queries\ClassroomQuery
     */
    public function getClassroom()
    {
        return $this->hasOne(Classroom::className(), ['classroom_id' => 'classroom_id']);
    }

    /**
     * Gets query for [[Day]].
     *
     * @return \yii\db\ActiveQuery|\app\models\queries\DayQuery
     */
    public function getDay()
    {
        return $this->hasOne(Day::className(), ['day_id' => 'day_id']);
    }

    /**
     * Gets query for [[LessonNum]].
     *
     * @return \yii\db\ActiveQuery|\app\models\queries\LessonNumQuery
     */
    public function getLessonNum()
    {
        return $this->hasOne(LessonNum::className(), ['lesson_num_id' => 'lesson_num_id']);
    }

    /**
     * Gets query for [[LessonPlan]].
     *
     * @return \yii\db\ActiveQuery|\app\models\queries\LessonPlanQuery
     */
    public function getLessonPlan()
    {
        return $this->hasOne(LessonPlan::className(), ['lesson_plan_id' => 'lesson_plan_id']);
    }

    /**
     * {@inheritdoc}
     * @return \app\models\queries\ScheduleQuery the active query used by this AR class.
     */
    public static function find()
    {
        return new \app\models\queries\ScheduleQuery(get_called_class());
    }
}
