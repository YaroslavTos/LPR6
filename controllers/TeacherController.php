<?php

namespace app\controllers;

use yii\data\ActiveDataProvider;
use app\models\Teacher;
use Yii;
use yii\helpers\Url;
use yii\web\ServerErrorHttpException;
use yii\web\NotFoundHttpException;

class TeacherController extends BaseController
{
    public function actionIndex()
    {
        return new ActiveDataProvider([
            'query' => Teacher::find()->with('user'),
        ]);
    }

    public function actionCreate()
    {
        $teacher = new Teacher();
        return $this->saveModel($teacher);
    }


    public function actionUpdate($id)
    {
        $teacher = $this->findModel($id);
        return $this->saveModel($teacher);
    }

    public function actionView($id)
    {
        return $this->findModel($id);
    }

    public function findModel($id)
    {
        $teacher = Teacher::findOne($id);
        if ($teacher === null) {
            throw new NotFoundHttpException("Teacher with ID $id not found");
        }
        return $teacher;
    }

    public function saveModel($teacher)
    {
        if ($teacher->loadAndSave(Yii::$app->getRequest()
            ->getBodyParams())) {
        $response = Yii::$app->getResponse();
        $response->setStatusCode(201);
        $response->getHeaders()->set('Location',
            Url::toRoute(['view', 'id' => $teacher
                ->getPrimaryKey()], true));
} elseif (!$teacher->hasErrors()) {
throw new
ServerErrorHttpException(serialize($teacher
    ->getErrors()));
}

return $teacher;
    }



}